// src/routers/auth_apoderado.ts
import type { FastifyInstance, FastifyPluginOptions } from "fastify";
import jwt from "jsonwebtoken";
import * as argon2 from "@node-rs/argon2";
import { z } from "zod";
import { getDb } from "../db";
import { CONFIG } from "../config";

/* ──────────────────────────────────────────────────────────────
   Config / constants
────────────────────────────────────────────────────────────── */
const JWT_ISSUER =
  String((CONFIG as any)?.JWT_ISSUER ?? process.env.JWT_ISSUER ?? "app").trim();
const JWT_AUDIENCE =
  String((CONFIG as any)?.JWT_AUDIENCE ?? process.env.JWT_AUDIENCE ?? "web").trim();

const PERF_LOG =
  String((CONFIG as any)?.AUTH_PERF_LOG ?? process.env.AUTH_PERF_LOG ?? "0") === "1";

/**
 * ✅ NinjaHosting / Node App Manager:
 * Por defecto NO confiamos en XFF porque el cliente puede spoofearlo.
 * Actívalo solo si confirmas proxy confiable que normaliza headers.
 */
const TRUST_PROXY =
  String((CONFIG as any)?.TRUST_PROXY ?? process.env.TRUST_PROXY ?? "0") === "1";

// ✅ Disponibilidad: limita concurrencia de Argon2 (anti CPU spike)
const MAX_AUTH_CONCURRENCY = Math.max(
  2,
  Number((CONFIG as any)?.AUTH_CONCURRENCY ?? process.env.AUTH_CONCURRENCY ?? 8) || 8
);

// ✅ Trunca audit extra para no inflar BD
const AUDIT_EXTRA_MAX_CHARS = Math.max(
  512,
  Number(
    (CONFIG as any)?.AUDIT_EXTRA_MAX_CHARS ??
      process.env.AUDIT_EXTRA_MAX_CHARS ??
      2048
  ) || 2048
);

function getJwtSecret() {
  const s = CONFIG.JWT_SECRET;
  if (!s) throw new Error("JWT_SECRET missing (CONFIG.JWT_SECRET)");
  return s;
}

/* ──────────────────────────────────────────────────────────────
   Validation
────────────────────────────────────────────────────────────── */
const RutSchema = z.string().regex(/^\d{7,8}$/);

const LoginSchema = z.object({
  rut: RutSchema,
  password: z.string().min(1),
});

const ChangePasswordSchema = z.object({
  current_password: z.string().min(1),
  new_password: z.string().min(8),
});

type ApoderadoToken = { type: "apoderado"; apoderado_id: number; rut: string };

/* ──────────────────────────────────────────────────────────────
   Small semaphore (limits argon2 concurrency)
────────────────────────────────────────────────────────────── */
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

/* ──────────────────────────────────────────────────────────────
   Token helpers
────────────────────────────────────────────────────────────── */
function signApoderadoToken(payload: ApoderadoToken) {
  const JWT_SECRET = getJwtSecret();
  if (!JWT_ISSUER) throw new Error("JWT_ISSUER missing");
  if (!JWT_AUDIENCE) throw new Error("JWT_AUDIENCE missing");

  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: "12h",
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  });
}

function verifyApoderadoToken(authHeader?: string): ApoderadoToken | null {
  if (!authHeader) return null;
  const [bearer, token] = authHeader.split(" ");
  if (bearer !== "Bearer" || !token) return null;

  try {
    const JWT_SECRET = getJwtSecret();

    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    }) as any;

    if (decoded?.type !== "apoderado") return null;

    const rut = String(decoded?.rut ?? "");
    const apoderado_id = Number(decoded?.apoderado_id);

    if (!/^\d{7,8}$/.test(rut)) return null;
    if (!Number.isInteger(apoderado_id) || apoderado_id <= 0) return null;

    return { type: "apoderado", rut, apoderado_id };
  } catch {
    return null;
  }
}

function getTokenOr401(req: any, reply: any): ApoderadoToken | null {
  const tokenData = verifyApoderadoToken(req.headers.authorization);
  if (!tokenData) {
    reply.code(401).send({ ok: false, message: "UNAUTHORIZED" });
    return null;
  }
  return tokenData;
}

/* ──────────────────────────────────────────────────────────────
   IP helper (anti spoof)
────────────────────────────────────────────────────────────── */
function getIp(req: any): string | null {
  if (!TRUST_PROXY) return req.ip ? String(req.ip) : null;

  const xff = req.headers?.["x-forwarded-for"];
  if (Array.isArray(xff)) return String(xff[0] || "").split(",")[0].trim() || null;
  if (typeof xff === "string" && xff) return xff.split(",")[0].trim() || null;

  const realIp = req.headers?.["x-real-ip"];
  if (typeof realIp === "string" && realIp) return realIp.trim();

  return req.ip ? String(req.ip) : null;
}

/* ──────────────────────────────────────────────────────────────
   Audit helpers (auth_audit)
────────────────────────────────────────────────────────────── */
type AuditEvent = "login" | "logout" | "refresh" | "invalid_token" | "access_denied";

function safeJsonTruncate(extra: any, maxChars: number) {
  if (!extra) return null;
  try {
    const s = JSON.stringify(extra);
    return s.length <= maxChars ? s : s.slice(0, maxChars);
  } catch {
    return null;
  }
}

async function auditApoderado(params: {
  req: any;
  event: AuditEvent;
  statusCode: number;
  apoderadoId?: number | null;
  extra?: any;
}) {
  const { req, event, statusCode, apoderadoId = null, extra = null } = params;

  try {
    const db = getDb();

    const route =
      String(req.routerPath ?? req.raw?.url ?? req.url ?? "").slice(0, 255) || null;

    const method = String(req.method ?? req.raw?.method ?? "").slice(0, 10) || null;

    const ip = getIp(req);
    const ua = String(req.headers?.["user-agent"] ?? "").slice(0, 255) || null;

    await db.query(
      `
      INSERT INTO auth_audit
        (user_id, event, route, method, status_code, ip, user_agent, extra, actor_type, actor_id)
      VALUES
        (NULL, ?, ?, ?, ?, ?, ?, ?, 'apoderado', ?)
      `,
      [
        event,
        route,
        method,
        statusCode ?? null,
        ip,
        ua,
        safeJsonTruncate(extra, AUDIT_EXTRA_MAX_CHARS),
        apoderadoId,
      ]
    );
  } catch {
    // no reventamos el flujo
  }
}

function fireAndForgetAudit(p: Parameters<typeof auditApoderado>[0]) {
  void auditApoderado(p).catch(() => {});
}

/* ──────────────────────────────────────────────────────────────
   Rate limit (in-memory) + GC
────────────────────────────────────────────────────────────── */
const RL_MAX = 8;
const RL_WINDOW_MS = 10 * 60_000;
const RL_BLOCK_MS = 15 * 60_000;

const RL_MAX_KEYS = 50_000;
const RL_GC_INTERVAL_MS = 60_000;

type RLState = { count: number; windowStart: number; blockedUntil: number; lastSeen: number };
const rl = new Map<string, RLState>();

function rlKey(ip: string | null, rut: string) {
  return `${ip || "noip"}:${rut}`;
}

function rlSafeKeysOk() {
  return rl.size < RL_MAX_KEYS;
}

/**
 * ✅ Cuenta intentos dentro de ventana (además de bloquear por fallos).
 * - Si está bloqueado → 429
 * - Si excede RL_MAX en ventana → bloquea
 */
function checkRateLimit(ip: string | null, rut: string) {
  const now = Date.now();
  const key = rlSafeKeysOk() ? rlKey(ip, rut) : `${ip || "noip"}:*`; // degradación segura
  const st = rl.get(key);

  if (!st) {
    rl.set(key, { count: 1, windowStart: now, blockedUntil: 0, lastSeen: now });
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

  st.count += 1;

  if (st.count >= RL_MAX) {
    st.blockedUntil = now + RL_BLOCK_MS;
    st.count = 0;
    st.windowStart = now;
    return { ok: false, retryAfterSec: Math.ceil(RL_BLOCK_MS / 1000) };
  }

  rl.set(key, st);
  return { ok: true, retryAfterSec: 0 };
}

function registerFailed(ip: string | null, rut: string) {
  const now = Date.now();
  const key = rlSafeKeysOk() ? rlKey(ip, rut) : `${ip || "noip"}:*`; // degradación segura
  const st = rl.get(key) ?? { count: 0, windowStart: now, blockedUntil: 0, lastSeen: now };

  st.lastSeen = now;

  if (now - st.windowStart > RL_WINDOW_MS) {
    st.count = 0;
    st.windowStart = now;
    st.blockedUntil = 0;
  }

  // “fail bias”: suma extra para castigar brute force real
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
      if (now - st.lastSeen > 60 * 60_000) rl.delete(k); // 1h sin uso
      else if (st.blockedUntil === 0 && now - st.windowStart > 2 * RL_WINDOW_MS) rl.delete(k);
    }
  }, RL_GC_INTERVAL_MS).unref?.();
}

/* ──────────────────────────────────────────────────────────────
   Dummy hash (timing equalization)
────────────────────────────────────────────────────────────── */
const DUMMY_HASH_PROMISE = withAuthSlot(() => argon2.hash("dummy-password-not-valid"));

/* ──────────────────────────────────────────────────────────────
   Hash params razonables
────────────────────────────────────────────────────────────── */
const ARGON2_HASH_OPTS: Parameters<typeof argon2.hash>[1] = {
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

/* ──────────────────────────────────────────────────────────────
   Router (prefix: /api/auth-apoderado)
────────────────────────────────────────────────────────────── */
export default async function auth_apoderado(
  app: FastifyInstance,
  _opts: FastifyPluginOptions
) {
  startRlGcOnce();

  app.post("/login", async (req, reply) => {
    const parsed = LoginSchema.safeParse(req.body);
    if (!parsed.success) {
      fireAndForgetAudit({
        req,
        event: "access_denied",
        statusCode: 400,
        apoderadoId: null,
        extra: { where: "login", reason: "BAD_REQUEST" },
      });
      return reply.code(400).send({ ok: false, message: "BAD_REQUEST" });
    }

    const { rut, password } = parsed.data;
    const db = getDb();
    const ip = getIp(req);

    const rlCheck = checkRateLimit(ip, rut);
    if (!rlCheck.ok) {
      fireAndForgetAudit({
        req,
        event: "access_denied",
        statusCode: 429,
        apoderadoId: null,
        extra: {
          where: "login",
          rut,
          reason: "RATE_LIMIT",
          retryAfterSec: rlCheck.retryAfterSec,
        },
      });
      reply.header("Retry-After", String(rlCheck.retryAfterSec));
      return reply.code(429).send({ ok: false, message: "TOO_MANY_ATTEMPTS" });
    }

    const t0 = Date.now();

    const [rows] = await db.query<any[]>(
      `SELECT apoderado_id, rut_apoderado, password_hash, must_change_password
         FROM apoderados_auth
        WHERE rut_apoderado = ?
        LIMIT 1`,
      [rut]
    );

    const t1 = Date.now();
    const auth = rows?.length ? rows[0] : null;
    const apoderadoId = auth ? Number(auth.apoderado_id) || null : null;

    const hashToVerify = auth?.password_hash ?? (await DUMMY_HASH_PROMISE);

    const t2a = Date.now();
    const ok = await withAuthSlot(async () => {
      try {
        return await argon2.verify(hashToVerify, password);
      } catch {
        return false;
      }
    });
    const t2b = Date.now();

    if (PERF_LOG) {
      console.log("[AUTH_APODERADO PERF]", {
        rut,
        ip,
        ms_select: t1 - t0,
        ms_argon2_verify: t2b - t2a,
        ms_total_so_far: t2b - t0,
        has_user: Boolean(auth),
        argon2_inflight: authSem.inFlight,
        rl_keys: rl.size,
        trust_proxy: TRUST_PROXY,
      });
    }

    if (!auth || !ok) {
      registerFailed(ip, rut);

      fireAndForgetAudit({
        req,
        event: "login",
        statusCode: 401,
        apoderadoId,
        extra: {
          rut,
          ok: false,
          reason: !auth ? "NO_USER" : "BAD_PASSWORD",
          ms_db: t1 - t0,
          ms_hash: t2b - t2a,
          ms_total: t2b - t0,
        },
      });

      return reply.code(401).send({ ok: false, message: "INVALID_CREDENTIALS" });
    }

    const token = signApoderadoToken({
      type: "apoderado",
      rut,
      apoderado_id: Number(auth.apoderado_id),
    });

    const t3a = Date.now();
    try {
      await db.query(
        `UPDATE apoderados_auth
            SET last_login_at = NOW()
          WHERE apoderado_id = ?
          LIMIT 1`,
        [Number(auth.apoderado_id)]
      );
    } catch {}
    const t3b = Date.now();

    fireAndForgetAudit({
      req,
      event: "login",
      statusCode: 200,
      apoderadoId: Number(auth.apoderado_id),
      extra: {
        rut,
        ok: true,
        must_change_password: Number(auth.must_change_password) === 1,
        ms_db: t1 - t0,
        ms_hash: t2b - t2a,
        ms_update: t3b - t3a,
        ms_total: Date.now() - t0,
      },
    });

    return reply.send({
      ok: true,
      token,
      must_change_password: Number(auth.must_change_password) === 1,
    });
  });

  app.post("/logout", async (req, reply) => {
    const tokenData = getTokenOr401(req, reply);
    if (!tokenData) {
      fireAndForgetAudit({
        req,
        event: "logout",
        statusCode: 401,
        apoderadoId: null,
        extra: { ok: false, reason: "UNAUTHORIZED" },
      });
      return;
    }

    fireAndForgetAudit({
      req,
      event: "logout",
      statusCode: 200,
      apoderadoId: tokenData.apoderado_id,
      extra: { rut: tokenData.rut, ok: true },
    });

    return reply.send({ ok: true });
  });

  app.get("/me", async (req, reply) => {
    const tokenData = getTokenOr401(req, reply);
    if (!tokenData) {
      fireAndForgetAudit({
        req,
        event: "invalid_token",
        statusCode: 401,
        apoderadoId: null,
        extra: { where: "me" },
      });
      return;
    }

    const db = getDb();

    const [rows] = await db.query<any[]>(
      `SELECT apoderado_id, rut_apoderado, must_change_password, last_login_at, created_at, updated_at
         FROM apoderados_auth
        WHERE apoderado_id = ?
        LIMIT 1`,
      [tokenData.apoderado_id]
    );

    if (!rows?.length) {
      fireAndForgetAudit({
        req,
        event: "invalid_token",
        statusCode: 401,
        apoderadoId: tokenData.apoderado_id,
        extra: { where: "me", reason: "NOT_FOUND" },
      });
      return reply.code(401).send({ ok: false, message: "UNAUTHORIZED" });
    }

    return reply.send({ ok: true, apoderado: rows[0] });
  });

  app.post("/change-password", async (req, reply) => {
    const tokenData = getTokenOr401(req, reply);
    if (!tokenData) {
      fireAndForgetAudit({
        req,
        event: "access_denied",
        statusCode: 401,
        apoderadoId: null,
        extra: { where: "change-password" },
      });
      return;
    }

    const parsed = ChangePasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      fireAndForgetAudit({
        req,
        event: "access_denied",
        statusCode: 400,
        apoderadoId: tokenData.apoderado_id,
        extra: { where: "change-password", reason: "BAD_REQUEST" },
      });
      return reply.code(400).send({ ok: false, message: "BAD_REQUEST" });
    }

    const db = getDb();

    const [rows] = await db.query<any[]>(
      `SELECT apoderado_id, password_hash
         FROM apoderados_auth
        WHERE apoderado_id = ?
        LIMIT 1`,
      [tokenData.apoderado_id]
    );

    if (!rows?.length) {
      fireAndForgetAudit({
        req,
        event: "access_denied",
        statusCode: 401,
        apoderadoId: tokenData.apoderado_id,
        extra: { where: "change-password", reason: "NOT_FOUND" },
      });
      return reply.code(401).send({ ok: false, message: "UNAUTHORIZED" });
    }

    const ok = await withAuthSlot(async () => {
      try {
        return await argon2.verify(rows[0].password_hash, parsed.data.current_password);
      } catch {
        return false;
      }
    });

    if (!ok) {
      fireAndForgetAudit({
        req,
        event: "access_denied",
        statusCode: 401,
        apoderadoId: tokenData.apoderado_id,
        extra: { where: "change-password", reason: "INVALID_CURRENT_PASSWORD" },
      });
      return reply.code(401).send({ ok: false, message: "INVALID_CURRENT_PASSWORD" });
    }

    const newHash = await withAuthSlot(() =>
      argon2.hash(parsed.data.new_password, ARGON2_HASH_OPTS)
    );

    await db.query(
      `UPDATE apoderados_auth
          SET password_hash = ?,
              must_change_password = 0,
              updated_at = NOW()
        WHERE apoderado_id = ?
        LIMIT 1`,
      [newHash, tokenData.apoderado_id]
    );

    fireAndForgetAudit({
      req,
      event: "refresh",
      statusCode: 200,
      apoderadoId: tokenData.apoderado_id,
      extra: { where: "change-password", ok: true },
    });

    return reply.send({ ok: true });
  });
}
