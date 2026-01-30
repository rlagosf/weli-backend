// src/routers/auth.ts
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { verify as argon2Verify, hash as argon2Hash } from "@node-rs/argon2";
import jwt, { SignOptions } from "jsonwebtoken";
import { db } from "../db";
import { CONFIG } from "../config";

/* ───────────────────────── Config ───────────────────────── */

const ALLOWED_PANEL_ROLES = new Set([1, 2]); // 1=admin, 2=staff
const ACTIVE_ESTADO_ID = 1;

// ✅ Identidad JWT (purga de "rafc"): configurable por env / CONFIG
// - Define JWT_ISSUER y JWT_AUDIENCE en tu config o .env si quieres valores específicos
// - Fallbacks neutros para no romper login si aún no los agregas
const JWT_ISSUER =
  String((CONFIG as any)?.JWT_ISSUER ?? process.env.JWT_ISSUER ?? "app").trim();
const JWT_AUDIENCE =
  String((CONFIG as any)?.JWT_AUDIENCE ?? process.env.JWT_AUDIENCE ?? "web").trim();

// Perf log opcional: AUTH_PERF_LOG=1
const PERF_LOG =
  String((CONFIG as any)?.AUTH_PERF_LOG ?? process.env.AUTH_PERF_LOG ?? "0") === "1";

/* ───────────────────────── Auditoría ───────────────────────── */

type AuditEvent = "login" | "logout" | "refresh" | "invalid_token" | "access_denied";

function getIp(req: FastifyRequest): string | null {
  const xff = req.headers?.["x-forwarded-for"];
  if (Array.isArray(xff)) return String(xff[0] || "").split(",")[0].trim() || null;
  if (typeof xff === "string" && xff) return xff.split(",")[0].trim() || null;

  const realIp = req.headers?.["x-real-ip"];
  if (typeof realIp === "string" && realIp) return realIp.trim();

  return (req as any).ip ? String((req as any).ip) : null;
}

async function audit(
  event: AuditEvent,
  req: FastifyRequest,
  status: number,
  userId?: number | null,
  extra?: any
) {
  try {
    const ip = getIp(req);
    const userAgent = (req.headers["user-agent"] as string) || null;
    const route = req.raw?.url || "";
    const method = req.method || "GET";

    await db.query(
      `INSERT INTO auth_audit
       (user_id, event, route, method, status_code, ip, user_agent, extra)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        userId ?? null,
        event,
        route.substring(0, 255),
        method.substring(0, 10),
        status,
        ip?.toString().substring(0, 64),
        userAgent?.substring(0, 255),
        extra ? JSON.stringify(extra) : null,
      ]
    );
  } catch {
    // auditoría nunca debe botar auth
  }
}

function fireAndForgetAudit(...args: Parameters<typeof audit>) {
  void audit(...args).catch(() => {});
}

/* ───────────────────────── Rate limit login (memoria) ─────────────────────────
   Producción multi-instancia: Redis/Upstash ideal
──────────────────────────────────────────────────────────────────────────── */

const RL_MAX = 10;
const RL_WINDOW_MS = 10 * 60_000;
const RL_BLOCK_MS = 15 * 60_000;

type RLState = { count: number; windowStart: number; blockedUntil: number };
const rl = new Map<string, RLState>();

function rlKey(ip: string | null, nombre_usuario: string) {
  return `${ip || "noip"}:${String(nombre_usuario || "").toLowerCase()}`;
}

function checkRateLimit(ip: string | null, nombre_usuario: string) {
  const key = rlKey(ip, nombre_usuario);
  const now = Date.now();
  const st = rl.get(key);

  if (!st) {
    rl.set(key, { count: 0, windowStart: now, blockedUntil: 0 });
    return { ok: true, retryAfterSec: 0 };
  }

  if (st.blockedUntil > now) {
    return { ok: false, retryAfterSec: Math.ceil((st.blockedUntil - now) / 1000) };
  }

  if (now - st.windowStart > RL_WINDOW_MS) {
    st.count = 0;
    st.windowStart = now;
    st.blockedUntil = 0;
  }

  return { ok: true, retryAfterSec: 0 };
}

function registerFailed(ip: string | null, nombre_usuario: string) {
  const key = rlKey(ip, nombre_usuario);
  const now = Date.now();
  const st = rl.get(key) ?? { count: 0, windowStart: now, blockedUntil: 0 };

  if (now - st.windowStart > RL_WINDOW_MS) {
    st.count = 0;
    st.windowStart = now;
    st.blockedUntil = 0;
  }

  st.count += 1;

  if (st.count >= RL_MAX) {
    st.blockedUntil = now + RL_BLOCK_MS;
    st.count = 0;
    st.windowStart = now;
  }

  rl.set(key, st);
}

/* ───────────────────────── Anti-timing dummy hash ───────────────────────── */

const DUMMY_HASH_PROMISE = argon2Hash("dummy-password-not-valid");

/* ───────────────────────── Helpers ───────────────────────── */

function getBearerToken(req: FastifyRequest) {
  const h = (req.headers.authorization || "").trim();
  const [type, token] = h.split(" ");
  if (type !== "Bearer" || !token) return null;
  return token;
}

async function requireAuth(req: FastifyRequest, reply: FastifyReply) {
  const token = getBearerToken(req);
  if (!token) {
    fireAndForgetAudit("access_denied", req, 401, null, { reason: "missing_token" });
    return reply.code(401).send({ ok: false, message: "Token requerido" });
  }

  let decoded: any;
  try {
    decoded = jwt.verify(token, CONFIG.JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });
  } catch {
    fireAndForgetAudit("invalid_token", req, 401, null, { reason: "jwt_verify_failed" });
    return reply.code(401).send({ ok: false, message: "Token inválido" });
  }

  const userId = Number(decoded?.sub);
  if (!Number.isFinite(userId) || userId <= 0) {
    fireAndForgetAudit("invalid_token", req, 401, null, { reason: "invalid_sub" });
    return reply.code(401).send({ ok: false, message: "Token inválido" });
  }

  try {
    const [rows]: any = await db.query(
      `SELECT id, nombre_usuario, email, rol_id, estado_id
       FROM usuarios
       WHERE id = ?
       LIMIT 1`,
      [userId]
    );

    if (!rows?.length) {
      fireAndForgetAudit("access_denied", req, 401, userId, { reason: "user_not_found" });
      return reply.code(401).send({ ok: false, message: "No autorizado" });
    }

    const user = rows[0];
    const rol = Number(user.rol_id);
    const estado = Number(user.estado_id);

    if (estado !== ACTIVE_ESTADO_ID) {
      fireAndForgetAudit("access_denied", req, 403, user.id, {
        reason: "user_inactive",
        estado_id: estado,
      });
      return reply.code(403).send({ ok: false, message: "Usuario inactivo" });
    }

    if (!ALLOWED_PANEL_ROLES.has(rol)) {
      fireAndForgetAudit("access_denied", req, 403, user.id, {
        reason: "role_not_allowed",
        rol_id: rol,
      });
      return reply.code(403).send({ ok: false, message: "No autorizado" });
    }

    (req as any).user = {
      id: user.id,
      nombre_usuario: user.nombre_usuario,
      email: user.email,
      rol_id: rol,
      estado_id: estado,
    };
  } catch (err: any) {
    req.log.error({ err }, "requireAuth failed");
    fireAndForgetAudit("access_denied", req, 500, userId, {
      reason: "db_error",
      message: err?.message,
    });
    return reply.code(500).send({ ok: false, message: "Error de autenticación" });
  }
}

/* ───────────────────────── Schemas ───────────────────────── */

const LoginSchema = z.object({
  nombre_usuario: z.string().min(3).max(80),
  password: z.string().min(4).max(200),
});

/* ───────────────────────── Router ───────────────────────── */

export default async function auth(app: FastifyInstance) {
  app.get("/health", async () => ({
    module: "auth",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  app.post(
    "/login",
    { schema: { security: [] } },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = LoginSchema.safeParse(req.body);
      if (!parsed.success) {
        fireAndForgetAudit("access_denied", req, 400, null, { reason: "invalid_payload" });
        return reply.code(400).send({ ok: false, message: "Payload inválido" });
      }

      const ip = getIp(req);
      const nombre_usuario = String(parsed.data.nombre_usuario ?? "").trim();
      const password = String(parsed.data.password ?? "");

      const rlCheck = checkRateLimit(ip, nombre_usuario);
      if (!rlCheck.ok) {
        fireAndForgetAudit("access_denied", req, 429, null, {
          reason: "rate_limit",
          nombre_usuario,
          retryAfterSec: rlCheck.retryAfterSec,
        });
        reply.header("Retry-After", String(rlCheck.retryAfterSec));
        return reply.code(429).send({ ok: false, message: "TOO_MANY_ATTEMPTS" });
      }

      const t0 = Date.now();

      try {
        // ✅ Cortamos antes: solo activos + rol permitido
        const [rows]: any = await db.query(
          `SELECT id, nombre_usuario, email, password, rol_id, estado_id
           FROM usuarios
           WHERE nombre_usuario = BINARY ?
             AND estado_id = ?
             AND rol_id IN (1,2)
           LIMIT 1`,
          [nombre_usuario, ACTIVE_ESTADO_ID]
        );

        const t1 = Date.now();

        const user = rows?.length ? rows[0] : null;

        // ✅ Anti-timing: verify siempre
        const hashToVerify = user?.password ?? (await DUMMY_HASH_PROMISE);

        const t2a = Date.now();
        let ok = false;
        try {
          ok = await argon2Verify(hashToVerify, password);
        } catch {
          ok = false;
        }
        const t2b = Date.now();

        if (PERF_LOG) {
          req.log.info(
            {
              nombre_usuario,
              ms_select: t1 - t0,
              ms_verify: t2b - t2a,
              ms_total_so_far: t2b - t0,
              has_user: Boolean(user),
            },
            "AUTH_ADMIN_LOGIN_PERF"
          );
        }

        if (!user || !ok) {
          registerFailed(ip, nombre_usuario);
          fireAndForgetAudit("access_denied", req, 401, user?.id ?? null, {
            reason: !user ? "user_not_found_or_not_allowed" : "bad_password",
            nombre_usuario,
            ms_total: t2b - t0,
          });
          return reply.code(401).send({ ok: false, message: "Credenciales inválidas" });
        }

        const rol = Number(user.rol_id);
        const estado = Number(user.estado_id);

        const payload = {
          sub: user.id,
          nombre_usuario: user.nombre_usuario,
          rol_id: rol,
          type: "panel",
        };

        const signOpts: SignOptions = {
          issuer: JWT_ISSUER,
          audience: JWT_AUDIENCE,
          expiresIn: (CONFIG.JWT_EXPIRES_IN as any) || "12h",
        };

        const token = jwt.sign(payload, CONFIG.JWT_SECRET, signOpts);

        fireAndForgetAudit("login", req, 200, user.id, { ok: true });

        return reply.send({
          ok: true,
          token,
          rol_id: rol,
          user: {
            id: user.id,
            nombre_usuario: user.nombre_usuario,
            email: user.email,
            rol_id: rol,
            estado_id: estado,
          },
        });
      } catch (err: any) {
        req.log.error({ err }, "auth/login failed");
        fireAndForgetAudit("access_denied", req, 500, null, {
          reason: "exception",
          message: err?.message,
        });
        return reply.code(500).send({ ok: false, message: "Error procesando login" });
      }
    }
  );

  app.post(
    "/logout",
    { preHandler: [requireAuth] },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const userId = (req as any).user?.id ?? null;
      fireAndForgetAudit("logout", req, 200, userId);
      return reply.send({ ok: true, message: "logout" });
    }
  );
}
