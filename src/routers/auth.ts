// src/routers/auth.ts

import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { verify as argon2Verify, hash as argon2Hash } from "@node-rs/argon2";
import jwt, { SignOptions } from "jsonwebtoken";
import { db } from "../db";
import { CONFIG } from "../config";
import { requireAuth as authzRequireAuth, requireRoles as authzRequireRoles } from "../middlewares/authz";

/* ───────────────────────── Config ───────────────────────── */

const ALLOWED_PANEL_ROLES = new Set([1, 2, 3]);
const ACTIVE_ESTADO_ID = 1;
const JWT_ALGORITHM = "HS256" as const;

const JWT_ISSUER = String((CONFIG as any)?.JWT_ISSUER ?? process.env.JWT_ISSUER ?? "app").trim();
const JWT_AUDIENCE = String((CONFIG as any)?.JWT_AUDIENCE ?? process.env.JWT_AUDIENCE ?? "web").trim();

const PERF_LOG = String((CONFIG as any)?.AUTH_PERF_LOG ?? process.env.AUTH_PERF_LOG ?? "0") === "1";
const TRUST_PROXY = String((CONFIG as any)?.TRUST_PROXY ?? process.env.TRUST_PROXY ?? "0") === "1";

const MAX_AUTH_CONCURRENCY = Math.max(
  2,
  Number((CONFIG as any)?.AUTH_CONCURRENCY ?? process.env.AUTH_CONCURRENCY ?? 8) || 8
);

const AUDIT_EXTRA_MAX_CHARS = Math.max(
  512,
  Number((CONFIG as any)?.AUDIT_EXTRA_MAX_CHARS ?? process.env.AUDIT_EXTRA_MAX_CHARS ?? 2048) || 2048
);

function getJwtSecret() {
  const secret = String(CONFIG.JWT_SECRET ?? process.env.JWT_SECRET ?? "");

  if (!secret) throw new Error("JWT_SECRET missing");
  if (secret.length < 32) throw new Error("JWT_SECRET must contain at least 32 characters");

  return secret;
}

/* ───────────────────────── JWT expiration ───────────────────────── */

type ExpiresIn = SignOptions["expiresIn"];

function normalizeExpiresIn(value: unknown): ExpiresIn {
  const FALLBACK: ExpiresIn = "12h";

  if (value == null) return FALLBACK;

  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return Math.floor(value);
  }

  const raw = String(value).trim();
  if (!raw) return FALLBACK;

  if (/^\d+$/.test(raw)) {
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : FALLBACK;
  }

  const compact = raw.replace(/\s+/g, "");
  if (/^\d+(ms|s|m|h|d|w|y)$/i.test(compact)) return compact as ExpiresIn;

  return FALLBACK;
}

/* ───────────────────────── Auditoría ───────────────────────── */

type AuditEvent = "login" | "logout" | "refresh" | "invalid_token" | "access_denied";

function getIp(req: FastifyRequest): string | null {
  if (!TRUST_PROXY) return (req as any).ip ? String((req as any).ip) : null;

  const xff = req.headers?.["x-forwarded-for"];

  if (Array.isArray(xff)) {
    return String(xff[0] || "").split(",")[0].trim() || null;
  }

  if (typeof xff === "string" && xff) {
    return xff.split(",")[0].trim() || null;
  }

  const realIp = req.headers?.["x-real-ip"];
  if (typeof realIp === "string" && realIp) return realIp.trim();

  return (req as any).ip ? String((req as any).ip) : null;
}

function safeJsonTruncate(extra: unknown, maxChars: number) {
  if (!extra) return null;

  try {
    const json = JSON.stringify(extra);
    return json.length <= maxChars ? json : json.slice(0, maxChars);
  } catch {
    return null;
  }
}

async function audit(
  event: AuditEvent,
  req: FastifyRequest,
  status: number,
  userId?: number | null,
  extra?: unknown
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
        ip?.toString().substring(0, 64) ?? null,
        userAgent?.substring(0, 255) ?? null,
        safeJsonTruncate(extra, AUDIT_EXTRA_MAX_CHARS),
      ]
    );
  } catch {
    // La auditoría nunca debe interrumpir el flujo de autenticación.
  }
}

function fireAndForgetAudit(...args: Parameters<typeof audit>) {
  void audit(...args).catch(() => {});
}

/* ───────────────────────── Semaphore Argon2 ───────────────────────── */

function createSemaphore(max: number) {
  let inFlight = 0;
  const queue: Array<() => void> = [];

  const acquire = () =>
    new Promise<void>((resolve) => {
      const run = () => {
        inFlight += 1;
        resolve();
      };

      if (inFlight < max) run();
      else queue.push(run);
    });

  const release = () => {
    inFlight = Math.max(0, inFlight - 1);
    const next = queue.shift();
    if (next) next();
  };

  return {
    acquire,
    release,
    get inFlight() {
      return inFlight;
    },
  };
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

/* ───────────────────────── Rate limit ───────────────────────── */

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
  return `${ip || "noip"}:${String(nombre_usuario || "").trim().toLowerCase()}`;
}

function rlFallbackKey(ip: string | null) {
  return `${ip || "noip"}:*`;
}

function rlSafeKeysOk() {
  return rl.size < RL_MAX_KEYS;
}

/**
 * Solo consulta el estado.
 * NO incrementa intentos.
 */
function checkRateLimit(ip: string | null, nombre_usuario: string) {
  const now = Date.now();
  const exactKey = rlKey(ip, nombre_usuario);

  /*
   * Cuando el mapa alcanza el máximo, registerFailed()
   * puede utilizar el bucket global por IP.
   * Por eso revisamos ambos.
   */
  const keys = [exactKey, rlFallbackKey(ip)];

  for (const key of keys) {
    const st = rl.get(key);
    if (!st) continue;

    st.lastSeen = now;

    if (st.blockedUntil > now) {
      return {
        ok: false,
        retryAfterSec: Math.ceil((st.blockedUntil - now) / 1000),
      };
    }

    if (now - st.windowStart > RL_WINDOW_MS) {
      rl.delete(key);
    }
  }

  return { ok: true, retryAfterSec: 0 };
}

/**
 * Único lugar donde se contabiliza un fallo real.
 */
function registerFailed(ip: string | null, nombre_usuario: string) {
  const now = Date.now();
  const key = rlSafeKeysOk() ? rlKey(ip, nombre_usuario) : rlFallbackKey(ip);

  const st =
    rl.get(key) ??
    ({
      count: 0,
      windowStart: now,
      blockedUntil: 0,
      lastSeen: now,
    } satisfies RLState);

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

/**
 * Login correcto:
 * elimina penalización previa de ese usuario/IP.
 */
function clearRateLimit(ip: string | null, nombre_usuario: string) {
  rl.delete(rlKey(ip, nombre_usuario));
}

let rlGcStarted = false;

function startRlGcOnce() {
  if (rlGcStarted) return;
  rlGcStarted = true;

  setInterval(() => {
    const now = Date.now();

    for (const [key, st] of rl.entries()) {
      if (now - st.lastSeen > 60 * 60_000) {
        rl.delete(key);
        continue;
      }

      if (st.blockedUntil === 0 && now - st.windowStart > 2 * RL_WINDOW_MS) {
        rl.delete(key);
      }
    }
  }, RL_GC_INTERVAL_MS).unref?.();
}

/* ───────────────────────── Anti timing ───────────────────────── */

/**
 * Hash dummy reutilizable:
 * evita una diferencia demasiado evidente entre
 * usuario existente e inexistente.
 */
const DUMMY_HASH_PROMISE = withAuthSlot(() => argon2Hash("weli-dummy-password-not-valid"));

/* ───────────────────────── Schemas ───────────────────────── */

const LoginSchema = z
  .object({
    nombre_usuario: z.string().trim().min(3).max(80),
    password: z.string().min(4).max(200),
    academia_id: z.coerce.number().int().positive().optional(),
  })
  .strict();

/* ───────────────────────── Router ───────────────────────── */

export default async function auth(app: FastifyInstance) {
  startRlGcOnce();

  /* ───────── Health ───────── */

  app.get("/health", async () => ({
    module: "auth",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  /* ───────── Login panel ───────── */

  app.post("/login", { schema: { security: [] } }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = LoginSchema.safeParse(req.body);

    if (!parsed.success) {
      fireAndForgetAudit("access_denied", req, 400, null, { reason: "invalid_payload" });
      return reply.code(400).send({ ok: false, message: "Payload inválido" });
    }

    const ip = getIp(req);
    const nombre_usuario = parsed.data.nombre_usuario.trim();
    const password = parsed.data.password;
    const academia_id_input =
      parsed.data.academia_id === undefined ? undefined : Number(parsed.data.academia_id);

    /* ───────── Rate limit ───────── */

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
      /* ───────── Usuario ───────── */

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

      /* ───────── Verificación Argon2 ───────── */

      const hashToVerify = user?.password ?? (await DUMMY_HASH_PROMISE);
      const t2a = Date.now();

      const passwordOk = await withAuthSlot(async () => {
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
          "AUTH_PANEL_LOGIN_PERF"
        );
      }

      /* ───────── Credenciales inválidas ───────── */

      if (!user || !passwordOk) {
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

      /* ───────── Rol ───────── */

      if (!ALLOWED_PANEL_ROLES.has(rol)) {
        fireAndForgetAudit("access_denied", req, 403, user.id, {
          reason: "role_not_allowed",
          rol_id: rol,
        });

        return reply.code(403).send({ ok: false, message: "No autorizado" });
      }

      /* ───────── Multi tenant ───────── */

      let academia_id_effective: number | null = null;

      if (rol === 3) {
        /*
         * Superadmin:
         * la academia se determina posteriormente mediante
         * x-academia-id en routers tenantizados.
         */
        academia_id_effective = null;
      } else {
        /*
         * Admin / Staff:
         * la academia se obtiene exclusivamente desde DB.
         */
        if (academiaIdDb == null || !Number.isFinite(academiaIdDb) || academiaIdDb <= 0) {
          fireAndForgetAudit("access_denied", req, 400, user.id, {
            reason: "user_missing_academia_id_db",
            rol_id: rol,
          });

          return reply.code(400).send({
            ok: false,
            message: "Usuario sin academia asignada. Contacta al administrador.",
          });
        }

        /*
         * Si el cliente envía academia_id,
         * solamente se utiliza para detectar inconsistencias.
         *
         * Nunca determina el tenant.
         */
        if (academia_id_input !== undefined && academiaIdDb !== academia_id_input) {
          fireAndForgetAudit("access_denied", req, 401, user.id, {
            reason: "academy_mismatch",
            rol_id: rol,
            academia_id_input,
            academia_id_db: academiaIdDb,
          });

          return reply.code(401).send({ ok: false, message: "Credenciales inválidas" });
        }

        academia_id_effective = academiaIdDb;
      }

      /*
       * Autenticación correcta:
       * limpia fallos anteriores de este usuario/IP.
       */
      clearRateLimit(ip, nombre_usuario);

      /* ───────── JWT WELI ───────── */

      const userIdStr = String(user.id);

      /*
       * Conservamos por ahora claims top-level + user
       * porque varios componentes actuales todavía leen
       * ambas estructuras.
       *
       * Esta compatibilidad se podrá retirar cuando terminemos
       * la purga global del proyecto.
       */
      const payload = {
        type: "admin",
        sub: userIdStr,
        rol_id: rol,
        nombre_usuario: String(user.nombre_usuario ?? ""),
        academia_id: academia_id_effective,

        user: {
          type: "admin",
          id: Number(user.id),
          rol_id: rol,
          nombre_usuario: String(user.nombre_usuario ?? ""),
          academia_id: academia_id_effective,
        },
      };

      const signOpts: SignOptions = {
        algorithm: JWT_ALGORITHM,
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
        expiresIn: normalizeExpiresIn((CONFIG as any).JWT_EXPIRES_IN ?? process.env.JWT_EXPIRES_IN),
      };

      let token: string;

      try {
        token = jwt.sign(payload, getJwtSecret(), signOpts);
      } catch (error: any) {
        req.log.error(
          {
            err: error,
            issuer: JWT_ISSUER,
            audience: JWT_AUDIENCE,
            algorithm: JWT_ALGORITHM,
            expiresIn: signOpts.expiresIn,
          },
          "[auth/login] jwt.sign failed"
        );

        fireAndForgetAudit("access_denied", req, 500, user.id, {
          reason: "jwt_sign_failed",
        });

        return reply.code(500).send({ ok: false, message: "Error procesando login" });
      }

      /* ───────── Auditoría login ───────── */

      fireAndForgetAudit("login", req, 200, user.id, {
        ok: true,
        rol_id: rol,
      });

      /* ───────── Respuesta ───────── */

      return reply.send({
        ok: true,
        token,
        rol_id: rol,

        user: {
          id: Number(user.id),
          nombre_usuario: String(user.nombre_usuario ?? ""),
          email: user.email,
          rol_id: rol,
          estado_id: estado,
          academia_id: academia_id_effective,
        },
      });
    } catch (error: any) {
      req.log.error({ err: error }, "auth/login failed");

      /*
       * No persistimos error.message en auth_audit:
       * puede contener detalles internos de DB o infraestructura.
       */
      fireAndForgetAudit("access_denied", req, 500, null, {
        reason: "exception",
      });

      return reply.code(500).send({
        ok: false,
        message: "Error procesando login",
      });
    }
  });

  /* ───────── Logout panel ───────── */

  app.post(
    "/logout",
    { preHandler: [authzRequireAuth, authzRequireRoles([1, 2, 3])] },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const auth = (req as any).auth;
      const userId = auth?.type === "user" ? auth?.user_id ?? null : null;

      fireAndForgetAudit("logout", req, 200, userId);

      return reply.send({
        ok: true,
        message: "logout",
      });
    }
  );
}