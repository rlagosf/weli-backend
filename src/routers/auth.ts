// src/routers/auth.ts
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { verify as argon2Verify, hash as argon2Hash } from "@node-rs/argon2";
import jwt, { SignOptions } from "jsonwebtoken";
import { db } from "../db";
import { CONFIG } from "../config";

/* ───────────────────────── Config ───────────────────────── */

// ✅ 1=admin, 2=staff, 3=superadmin
const ALLOWED_PANEL_ROLES = new Set([1, 2, 3]);
const ACTIVE_ESTADO_ID = 1;

const JWT_ISSUER =
  String((CONFIG as any)?.JWT_ISSUER ?? process.env.JWT_ISSUER ?? "app").trim();
const JWT_AUDIENCE =
  String((CONFIG as any)?.JWT_AUDIENCE ?? process.env.JWT_AUDIENCE ?? "web").trim();

const PERF_LOG =
  String((CONFIG as any)?.AUTH_PERF_LOG ?? process.env.AUTH_PERF_LOG ?? "0") === "1";

/**
 * ✅ NinjaHosting:
 * Por defecto NO confiamos en XFF (spoofable).
 * Activa solo si confirmas reverse proxy confiable que setea XFF.
 */
const TRUST_PROXY =
  String((CONFIG as any)?.TRUST_PROXY ?? process.env.TRUST_PROXY ?? "0") === "1";

/**
 * ✅ Disponibilidad:
 * Limita cuántos Argon2 pueden correr en paralelo (anti CPU spike).
 */
const MAX_AUTH_CONCURRENCY = Math.max(
  2,
  Number((CONFIG as any)?.AUTH_CONCURRENCY ?? process.env.AUTH_CONCURRENCY ?? 8) || 8
);

/**
 * ✅ Evita inflar la tabla auth_audit con extras gigantes.
 */
const AUDIT_EXTRA_MAX_CHARS = Math.max(
  512,
  Number(
    (CONFIG as any)?.AUDIT_EXTRA_MAX_CHARS ??
      process.env.AUDIT_EXTRA_MAX_CHARS ??
      2048
  ) || 2048
);

/* ───────────────────────── Auditoría ───────────────────────── */

type AuditEvent = "login" | "logout" | "refresh" | "invalid_token" | "access_denied";

function getIp(req: FastifyRequest): string | null {
  if (!TRUST_PROXY) return (req as any).ip ? String((req as any).ip) : null;

  const xff = req.headers?.["x-forwarded-for"];
  if (Array.isArray(xff)) return String(xff[0] || "").split(",")[0].trim() || null;
  if (typeof xff === "string" && xff) return xff.split(",")[0].trim() || null;

  const realIp = req.headers?.["x-real-ip"];
  if (typeof realIp === "string" && realIp) return realIp.trim();

  return (req as any).ip ? String((req as any).ip) : null;
}

function safeJsonTruncate(extra: any, maxChars: number) {
  if (!extra) return null;
  try {
    const s = JSON.stringify(extra);
    return s.length <= maxChars ? s : s.slice(0, maxChars);
  } catch {
    return null;
  }
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
        safeJsonTruncate(extra, AUDIT_EXTRA_MAX_CHARS),
      ]
    );
  } catch {
    // auditoría nunca debe botar auth
  }
}

function fireAndForgetAudit(...args: Parameters<typeof audit>) {
  void audit(...args).catch(() => {});
}

/* ───────────────────────── Semaphore (argon2) ───────────────────────── */

function createSemaphore(max: number) {
  let inFlight = 0;
  const q: Array<() => void> = [];

  const acquire = () =>
    new Promise<void>((resolve) => {
      const run = () => {
        inFlight += 1;
        resolve();
      };
      if (inFlight < max) run();
      else q.push(run);
    });

  const release = () => {
    inFlight = Math.max(0, inFlight - 1);
    const next = q.shift();
    if (next) next();
  };

  return { acquire, release, get inFlight() { return inFlight; } };
}

const authSem = createSemaphore(MAX_AUTH_CONCURRENCY);

async function withAuthSlot<T>(fn: () => Promise<T>): Promise<T> {
  await authSem.acquire();
  try {
    return await fn();
  } finally {
    authSem.release();
  }
}

/* ───────────────────────── Rate limit login (memoria) ───────────────────────── */

const RL_MAX = 10;
const RL_WINDOW_MS = 10 * 60_000;
const RL_BLOCK_MS = 15 * 60_000;

const RL_MAX_KEYS = 50_000;
const RL_GC_INTERVAL_MS = 60_000;

type RLState = {
  count: number;
  windowStart: number;
  blockedUntil: number;
  lastSeen: number;
};

const rl = new Map<string, RLState>();

function rlKey(ip: string | null, nombre_usuario: string) {
  return `${ip || "noip"}:${String(nombre_usuario || "").toLowerCase()}`;
}

function rlSafeKeysOk() {
  return rl.size < RL_MAX_KEYS;
}

function checkRateLimit(ip: string | null, nombre_usuario: string) {
  const now = Date.now();
  const key = rlSafeKeysOk() ? rlKey(ip, nombre_usuario) : `${ip || "noip"}:*`;

  const st = rl.get(key);
  if (!st) {
    rl.set(key, { count: 0, windowStart: now, blockedUntil: 0, lastSeen: now });
    return { ok: true, retryAfterSec: 0 };
  }

  st.lastSeen = now;

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
  const now = Date.now();
  const key = rlSafeKeysOk() ? rlKey(ip, nombre_usuario) : `${ip || "noip"}:*`;

  const st =
    rl.get(key) ?? { count: 0, windowStart: now, blockedUntil: 0, lastSeen: now };

  st.lastSeen = now;

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

let rlGcStarted = false;
function startRlGcOnce() {
  if (rlGcStarted) return;
  rlGcStarted = true;

  setInterval(() => {
    const now = Date.now();
    for (const [k, st] of rl.entries()) {
      if (now - st.lastSeen > 60 * 60_000) rl.delete(k);
      else if (st.blockedUntil === 0 && now - st.windowStart > 2 * RL_WINDOW_MS)
        rl.delete(k);
    }
  }, RL_GC_INTERVAL_MS).unref?.();
}

/* ───────────────────────── Anti-timing dummy hash ───────────────────────── */

const DUMMY_HASH_PROMISE = withAuthSlot(() => argon2Hash("dummy-password-not-valid"));

/* ───────────────────────── Helpers ───────────────────────── */

function getBearerToken(req: FastifyRequest) {
  const h = (req.headers.authorization || "").trim();
  const [type, token] = h.split(" ");
  if (type !== "Bearer" || !token) return null;
  return token;
}

// ✅ Incluimos academia_id en contexto de usuario autenticado
type ReqUser = {
  id: number;
  nombre_usuario: string;
  email: string | null;
  rol_id: number;
  estado_id: number;
  academia_id: number | null;
};

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

  // ✅ academia_id puede venir en token (más rápido) pero validamos en DB igual
  const tokenAcademiaId =
    decoded?.academia_id === null || decoded?.academia_id === undefined
      ? null
      : Number(decoded?.academia_id);

  try {
    const [rows]: any = await db.query(
      `SELECT id, nombre_usuario, email, rol_id, estado_id, academia_id
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
    const academiaIdDb = user.academia_id === null ? null : Number(user.academia_id);

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

    // ✅ Consistencia: si token trae academia_id, y es distinto a DB => token “viejo”
    if (
      tokenAcademiaId !== null &&
      academiaIdDb !== null &&
      Number.isFinite(tokenAcademiaId) &&
      tokenAcademiaId !== academiaIdDb
    ) {
      fireAndForgetAudit("invalid_token", req, 401, user.id, {
        reason: "academy_mismatch",
        tokenAcademiaId,
        academiaIdDb,
      });
      return reply.code(401).send({ ok: false, message: "Token inválido" });
    }

    (req as any).user = {
      id: user.id,
      nombre_usuario: user.nombre_usuario,
      email: user.email,
      rol_id: rol,
      estado_id: estado,
      academia_id: academiaIdDb,
    } satisfies ReqUser;

    return;
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

/**
 * ✅ Login multi-tenant:
 * - rol 3 (superadmin): NO requiere academia_id
 * - rol 1/2 (admin/staff): SÍ requiere academia_id
 *
 * Para esto:
 * - recibimos academia_id opcional
 * - después de obtener el usuario, aplicamos la regla.
 */
const LoginSchema = z.object({
  nombre_usuario: z.string().trim().min(3).max(80),
  password: z.string().min(4).max(200),
  academia_id: z.coerce.number().int().positive().optional(),
});

/* ───────────────────────── Router ───────────────────────── */

export default async function auth(app: FastifyInstance) {
  startRlGcOnce();

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
      const academia_id_input =
        parsed.data.academia_id === undefined ? undefined : Number(parsed.data.academia_id);

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
        /**
         * ✅ Importante:
         * - En primer query NO filtramos por academia_id aún, porque no sabemos el rol.
         * - Sí filtramos por estado activo para evitar comparar hashes de usuarios muertos.
         */
        const [rows]: any = await db.query(
          `SELECT id, nombre_usuario, email, password, rol_id, estado_id, academia_id
           FROM usuarios
           WHERE nombre_usuario = BINARY ?
             AND estado_id = ?
             AND rol_id IN (1,2,3)
           LIMIT 1`,
          [nombre_usuario, ACTIVE_ESTADO_ID]
        );

        const t1 = Date.now();
        const user = rows?.length ? rows[0] : null;

        const hashToVerify = user?.password ?? (await DUMMY_HASH_PROMISE);

        const t2a = Date.now();
        const ok = await withAuthSlot(async () => {
          try {
            return await argon2Verify(hashToVerify, password);
          } catch {
            return false;
          }
        });
        const t2b = Date.now();

        if (PERF_LOG) {
          req.log.info(
            {
              nombre_usuario,
              ip,
              ms_select: t1 - t0,
              ms_verify: t2b - t2a,
              ms_total_so_far: t2b - t0,
              has_user: Boolean(user),
              argon2_inflight: authSem.inFlight,
              rl_keys: rl.size,
              trust_proxy: TRUST_PROXY,
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
        const academiaIdDb = user.academia_id === null ? null : Number(user.academia_id);

        // ✅ Regla multi-tenant
        if (rol === 3) {
          // superadmin: NO requiere academia_id
          // (puede venir igual, pero no lo usamos como “scope” obligatorio)
        } else {
          // admin/staff: REQUIERE academia_id (y debe coincidir con el usuario)
          if (!academia_id_input || !Number.isFinite(academia_id_input) || academia_id_input <= 0) {
            fireAndForgetAudit("access_denied", req, 400, user.id, {
              reason: "missing_academia_id_for_role",
              rol_id: rol,
            });
            return reply.code(400).send({
              ok: false,
              message: "Debes seleccionar una academia para ingresar.",
            });
          }

          if (!academiaIdDb || academiaIdDb !== academia_id_input) {
            // No revelamos si existe otra academia o no: mensaje genérico
            fireAndForgetAudit("access_denied", req, 401, user.id, {
              reason: "academy_mismatch",
              rol_id: rol,
              academia_id_input,
              academia_id_db: academiaIdDb,
            });
            return reply.code(401).send({ ok: false, message: "Credenciales inválidas" });
          }
        }

        const payload = {
          sub: user.id,
          nombre_usuario: user.nombre_usuario,
          rol_id: rol,
          type: "panel",
          // ✅ academy scope:
          // - superadmin: null (o puedes omitirlo)
          // - admin/staff: academiaIdDb (validado)
          academia_id: rol === 3 ? null : academiaIdDb,
        };

        const signOpts: SignOptions = {
          issuer: JWT_ISSUER,
          audience: JWT_AUDIENCE,
          expiresIn: (CONFIG.JWT_EXPIRES_IN as any) || "12h",
        };

        const token = jwt.sign(payload, CONFIG.JWT_SECRET, signOpts);

        fireAndForgetAudit("login", req, 200, user.id, { ok: true, rol_id: rol });

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
            academia_id: rol === 3 ? null : academiaIdDb,
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
