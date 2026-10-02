// src/routers/auth_apoderado.ts

import type { FastifyInstance, FastifyPluginOptions } from "fastify";

import jwt from "jsonwebtoken";
import * as argon2 from "@node-rs/argon2";
import { z } from "zod";

import { getDb } from "../db";
import { CONFIG } from "../config";

import { decryptNullable, decryptRut, rutBlindIndex, validateCryptoConfiguration } from "../services/crypto";

/* =========================================================
   CONFIG
========================================================= */

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
  const secret = CONFIG.JWT_SECRET;

  if (!secret) {
    throw new Error("JWT_SECRET missing (CONFIG.JWT_SECRET)");
  }

  return secret;
}

/* =========================================================
   VALIDATION
========================================================= */

const RutSchema = z.string().regex(/^\d{7,8}$/);

const LoginSchema = z
  .object({
    rut: RutSchema,
    password: z.string().min(1),
  })
  .strict();

const ChangePasswordSchema = z
  .object({
    current_password: z.string().min(1),
    new_password: z.string().min(8),
  })
  .strict();

/* =========================================================
   TOKEN
========================================================= */

type ApoderadoToken = {
  type: "apoderado";
  apoderado_id: number;

  /*
   * Compatibilidad temporal.
   *
   * El RUT continúa dentro del JWT porque existen
   * consumidores actuales que aún dependen de él.
   *
   * La BD no almacena este dato en plaintext.
   */
  rut: string;
};

function signApoderadoToken(payload: ApoderadoToken) {
  const JWT_SECRET = getJwtSecret();

  if (!JWT_ISSUER) {
    throw new Error("JWT_ISSUER missing");
  }

  if (!JWT_AUDIENCE) {
    throw new Error("JWT_AUDIENCE missing");
  }

  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: "12h",
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  });
}

function verifyApoderadoToken(authHeader?: string): ApoderadoToken | null {
  if (!authHeader) {
    return null;
  }

  const [bearer, token] = authHeader.split(" ");

  if (bearer !== "Bearer" || !token) {
    return null;
  }

  try {
    const JWT_SECRET = getJwtSecret();

    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    }) as any;

    if (decoded?.type !== "apoderado") {
      return null;
    }

    const rut = String(decoded?.rut ?? "");

    const apoderadoId = Number(decoded?.apoderado_id);

    if (!/^\d{7,8}$/.test(rut)) {
      return null;
    }

    if (!Number.isInteger(apoderadoId) || apoderadoId <= 0) {
      return null;
    }

    return {
      type: "apoderado",
      rut,
      apoderado_id: apoderadoId,
    };
  } catch {
    return null;
  }
}

function getTokenOr401(req: any, reply: any): ApoderadoToken | null {
  const tokenData = verifyApoderadoToken(req.headers.authorization);

  if (!tokenData) {
    reply.code(401).send({
      ok: false,
      message: "UNAUTHORIZED",
    });

    return null;
  }

  return tokenData;
}

/* =========================================================
   ARGON2 SEMAPHORE
========================================================= */

function createSemaphore(max: number) {
  let inFlight = 0;

  const queue: Array<() => void> = [];

  const acquire = () =>
    new Promise<void>((resolve) => {
      const run = () => {
        inFlight += 1;
        resolve();
      };

      if (inFlight < max) {
        run();
      } else {
        queue.push(run);
      }
    });

  const release = () => {
    inFlight = Math.max(0, inFlight - 1);

    const next = queue.shift();

    if (next) {
      next();
    }
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

/* =========================================================
   IP
========================================================= */

function getIp(req: any): string | null {
  if (!TRUST_PROXY) {
    return req.ip ? String(req.ip) : null;
  }

  const xff = req.headers?.["x-forwarded-for"];

  if (Array.isArray(xff)) {
    return (
      String(xff[0] || "")
        .split(",")[0]
        .trim() || null
    );
  }

  if (typeof xff === "string" && xff) {
    return xff.split(",")[0].trim() || null;
  }

  const realIp = req.headers?.["x-real-ip"];

  if (typeof realIp === "string" && realIp) {
    return realIp.trim();
  }

  return req.ip ? String(req.ip) : null;
}

/* =========================================================
   AUDIT
========================================================= */

type AuditEvent = "login" | "logout" | "refresh" | "invalid_token" | "access_denied";

function safeJsonTruncate(extra: any, maxChars: number) {
  if (!extra) {
    return null;
  }

  try {
    const serialized = JSON.stringify(extra);

    return serialized.length <= maxChars ? serialized : serialized.slice(0, maxChars);
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

    const route = String(req.routerPath ?? req.raw?.url ?? req.url ?? "").slice(0, 255) || null;

    const method = String(req.method ?? req.raw?.method ?? "").slice(0, 10) || null;

    const ip = getIp(req);

    const ua = String(req.headers?.["user-agent"] ?? "").slice(0, 255) || null;

    await db.query(
      `
        INSERT INTO auth_audit
        (
          user_id,
          event,
          route,
          method,
          status_code,
          ip,
          user_agent,
          extra,
          actor_type,
          actor_id
        )
        VALUES
        (
          NULL,
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          'apoderado',
          ?
        )
      `,
      [event, route, method, statusCode ?? null, ip, ua, safeJsonTruncate(extra, AUDIT_EXTRA_MAX_CHARS), apoderadoId]
    );
  } catch {
    /*
     * La auditoría nunca debe romper
     * el flujo de autenticación.
     */
  }
}

function fireAndForgetAudit(params: Parameters<typeof auditApoderado>[0]) {
  void auditApoderado(params).catch(() => {});
}

/* =========================================================
   RATE LIMIT
========================================================= */

const RL_MAX = 8;

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

function rlKey(ip: string | null, rut: string) {
  /*
   * Sólo memoria.
   *
   * Nunca se persiste el RUT
   * de esta estructura.
   */
  return `${ip || "noip"}:${rut}`;
}

function rlFallbackKey(ip: string | null) {
  return `${ip || "noip"}:*`;
}

function rlSafeKeysOk() {
  return rl.size < RL_MAX_KEYS;
}

function checkRateLimit(ip: string | null, rut: string) {
  const now = Date.now();

  const normalKey = rlKey(ip, rut);

  const fallbackKey = rlFallbackKey(ip);

  const normalState = rl.get(normalKey);

  const fallbackState = rl.get(fallbackKey);

  const states: Array<{
    key: string;
    state: RLState;
  }> = [];

  if (normalState) {
    states.push({
      key: normalKey,
      state: normalState,
    });
  }

  if (fallbackState && fallbackKey !== normalKey) {
    states.push({
      key: fallbackKey,
      state: fallbackState,
    });
  }

  if (states.length === 0) {
    return {
      ok: true,
      retryAfterSec: 0,
    };
  }

  let maxRetryAfterSec = 0;

  for (const { key, state } of states) {
    state.lastSeen = now;

    if (state.blockedUntil > now) {
      const retryAfterSec = Math.ceil((state.blockedUntil - now) / 1000);

      maxRetryAfterSec = Math.max(maxRetryAfterSec, retryAfterSec);

      rl.set(key, state);

      continue;
    }

    if (state.blockedUntil > 0 && state.blockedUntil <= now) {
      rl.delete(key);

      continue;
    }

    if (now - state.windowStart > RL_WINDOW_MS) {
      rl.delete(key);

      continue;
    }

    rl.set(key, state);
  }

  if (maxRetryAfterSec > 0) {
    return {
      ok: false,
      retryAfterSec: maxRetryAfterSec,
    };
  }

  return {
    ok: true,
    retryAfterSec: 0,
  };
}

function registerFailed(ip: string | null, rut: string) {
  const now = Date.now();

  const key = rlSafeKeysOk() ? rlKey(ip, rut) : rlFallbackKey(ip);

  const existing = rl.get(key);

  const state: RLState = existing ?? {
    count: 0,
    windowStart: now,
    blockedUntil: 0,
    lastSeen: now,
  };

  state.lastSeen = now;

  if (state.blockedUntil > 0 && state.blockedUntil <= now) {
    state.count = 0;

    state.windowStart = now;

    state.blockedUntil = 0;
  }

  if (now - state.windowStart > RL_WINDOW_MS) {
    state.count = 0;

    state.windowStart = now;

    state.blockedUntil = 0;
  }

  state.count += 1;

  if (state.count >= RL_MAX) {
    state.count = RL_MAX;

    state.blockedUntil = now + RL_BLOCK_MS;
  }

  rl.set(key, state);
}

function clearRateLimit(ip: string | null, rut: string) {
  rl.delete(rlKey(ip, rut));

  rl.delete(rlFallbackKey(ip));
}

let rlGcStarted = false;

function startRlGcOnce() {
  if (rlGcStarted) {
    return;
  }

  rlGcStarted = true;

  setInterval(() => {
    const now = Date.now();

    for (const [key, state] of rl.entries()) {
      if (now - state.lastSeen > 60 * 60_000) {
        rl.delete(key);

        continue;
      }

      if (state.blockedUntil > 0 && state.blockedUntil <= now) {
        rl.delete(key);

        continue;
      }

      if (state.blockedUntil === 0 && now - state.windowStart > 2 * RL_WINDOW_MS) {
        rl.delete(key);
      }
    }
  }, RL_GC_INTERVAL_MS).unref?.();
}

/* =========================================================
   ARGON2
========================================================= */

const ARGON2_HASH_OPTS: Parameters<typeof argon2.hash>[1] = {
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

/*
 * Dummy hash para igualación temporal.
 *
 * Se genera una sola vez.
 */
const DUMMY_HASH_PROMISE = withAuthSlot(() => argon2.hash("dummy-password-not-valid", ARGON2_HASH_OPTS));

/* =========================================================
   ROUTER
========================================================= */

export default async function auth_apoderado(app: FastifyInstance, _opts: FastifyPluginOptions) {
  /*
   * El router requiere las claves
   * criptográficas correctamente configuradas.
   */
  validateCryptoConfiguration();

  startRlGcOnce();

  /* =======================================================
     LOGIN
  ======================================================= */

  app.post("/login", async (req, reply) => {
    const parsed = LoginSchema.safeParse(req.body);

    if (!parsed.success) {
      fireAndForgetAudit({
        req,
        event: "access_denied",
        statusCode: 400,
        apoderadoId: null,
        extra: {
          where: "login",
          reason: "BAD_REQUEST",
        },
      });

      return reply.code(400).send({
        ok: false,
        message: "BAD_REQUEST",
      });
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

          reason: "RATE_LIMIT",

          retryAfterSec: rlCheck.retryAfterSec,
        },
      });

      reply.header("Retry-After", String(rlCheck.retryAfterSec));

      return reply.code(429).send({
        ok: false,
        message: "TOO_MANY_ATTEMPTS",
      });
    }

    const t0 = Date.now();

    /*
     * Blind index:
     *
     * jamás buscamos el ciphertext
     * ni el RUT plaintext.
     */
    const rutIdx = rutBlindIndex(rut);

    const [rows] = await db.query<any[]>(
      `
            SELECT
              apoderado_id,
              password_hash,
              must_change_password,
              estado_id

            FROM apoderados_auth

            WHERE rut_apoderado_idx = ?

            LIMIT 1
          `,
      [rutIdx]
    );

    const t1 = Date.now();

    const auth = rows?.length ? rows[0] : null;

    /*
     * Sólo estado 1 puede autenticarse.
     *
     * La respuesta externa continúa siendo
     * INVALID_CREDENTIALS para no revelar
     * información sobre cuentas.
     */
    const authActivo = auth && Number(auth.estado_id) === 1 ? auth : null;

    const apoderadoId = authActivo ? Number(authActivo.apoderado_id) || null : null;

    /*
     * Timing equalization:
     *
     * cuenta inexistente o inactiva
     * sigue realizando Argon2.
     */
    const hashToVerify = authActivo?.password_hash ?? (await DUMMY_HASH_PROMISE);

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
        ip,

        ms_select: t1 - t0,

        ms_argon2_verify: t2b - t2a,

        ms_total_so_far: t2b - t0,

        /*
         * No revelamos si estaba inactivo.
         */
        has_user: Boolean(auth),

        auth_active: Boolean(authActivo),

        argon2_inflight: authSem.inFlight,

        rl_keys: rl.size,

        trust_proxy: TRUST_PROXY,
      });
    }

    /*
     * IMPORTANTE:
     *
     * aquí debe utilizarse authActivo,
     * NO auth.
     */
    if (!authActivo || !ok) {
      registerFailed(ip, rut);

      fireAndForgetAudit({
        req,

        event: "login",

        statusCode: 401,

        apoderadoId,

        extra: {
          ok: false,

          /*
           * Deliberadamente genérico.
           */
          reason: "INVALID_CREDENTIALS",

          ms_db: t1 - t0,

          ms_hash: t2b - t2a,

          ms_total: t2b - t0,
        },
      });

      return reply.code(401).send({
        ok: false,
        message: "INVALID_CREDENTIALS",
      });
    }

    /*
     * LOGIN CORRECTO.
     */
    clearRateLimit(ip, rut);

    /*
     * Compatibilidad temporal:
     * RUT sigue presente dentro del JWT.
     */
    const token = signApoderadoToken({
      type: "apoderado",

      rut,

      apoderado_id: Number(authActivo.apoderado_id),
    });

    const t3a = Date.now();

    try {
      await db.query(
        `
            UPDATE apoderados_auth

            SET
              last_login_at = NOW()

            WHERE apoderado_id = ?

            LIMIT 1
          `,
        [Number(authActivo.apoderado_id)]
      );
    } catch {
      /*
       * Un fallo de last_login_at
       * no invalida credenciales correctas.
       */
    }

    const t3b = Date.now();

    fireAndForgetAudit({
      req,

      event: "login",

      statusCode: 200,

      apoderadoId: Number(authActivo.apoderado_id),

      extra: {
        ok: true,

        must_change_password: Number(authActivo.must_change_password) === 1,

        ms_db: t1 - t0,

        ms_hash: t2b - t2a,

        ms_update: t3b - t3a,

        ms_total: Date.now() - t0,
      },
    });

    return reply.send({
      ok: true,

      token,

      must_change_password: Number(authActivo.must_change_password) === 1,
    });
  });

  /* =======================================================
     LOGOUT
  ======================================================= */

  app.post("/logout", async (req, reply) => {
    const tokenData = getTokenOr401(req, reply);

    if (!tokenData) {
      fireAndForgetAudit({
        req,

        event: "logout",

        statusCode: 401,

        apoderadoId: null,

        extra: {
          ok: false,
          reason: "UNAUTHORIZED",
        },
      });

      return;
    }

    fireAndForgetAudit({
      req,

      event: "logout",

      statusCode: 200,

      apoderadoId: tokenData.apoderado_id,

      extra: {
        ok: true,
      },
    });

    return reply.send({
      ok: true,
    });
  });

  /* =======================================================
     ME
  ======================================================= */

  app.get("/me", async (req, reply) => {
    const tokenData = getTokenOr401(req, reply);

    if (!tokenData) {
      fireAndForgetAudit({
        req,

        event: "invalid_token",

        statusCode: 401,

        apoderadoId: null,

        extra: {
          where: "me",
        },
      });

      return;
    }

    const db = getDb();

    const [rows] = await db.query<any[]>(
      `
            SELECT
              apoderado_id,

              rut_apoderado_enc,
              nombre_apoderado_enc,

              estado_id,
              must_change_password,

              last_login_at,
              created_at,
              updated_at

            FROM apoderados_auth

            WHERE apoderado_id = ?

            LIMIT 1
          `,
      [tokenData.apoderado_id]
    );

    if (!rows?.length) {
      fireAndForgetAudit({
        req,

        event: "invalid_token",

        statusCode: 401,

        apoderadoId: tokenData.apoderado_id,

        extra: {
          where: "me",

          reason: "NOT_FOUND",
        },
      });

      return reply.code(401).send({
        ok: false,

        message: "UNAUTHORIZED",
      });
    }

    const row = rows[0];

    /*
     * Un JWT válido deja de ser suficiente
     * si la cuenta fue desactivada.
     */
    if (Number(row.estado_id) !== 1) {
      fireAndForgetAudit({
        req,

        event: "access_denied",

        statusCode: 401,

        apoderadoId: tokenData.apoderado_id,

        extra: {
          where: "me",

          reason: "ACCOUNT_INACTIVE",
        },
      });

      return reply.code(401).send({
        ok: false,

        message: "UNAUTHORIZED",
      });
    }

    let rutApoderado: string;

    let nombreApoderado: string | null = null;

    try {
      rutApoderado = decryptRut(row.rut_apoderado_enc);

      const nombre = decryptNullable(row.nombre_apoderado_enc);

      nombreApoderado = nombre === null || nombre === undefined ? null : String(nombre).trim() || null;
    } catch {
      fireAndForgetAudit({
        req,

        event: "access_denied",

        statusCode: 500,

        apoderadoId: tokenData.apoderado_id,

        extra: {
          where: "me",

          reason: "DECRYPT_FAILED",
        },
      });

      return reply.code(500).send({
        ok: false,

        message: "AUTH_DATA_UNAVAILABLE",
      });
    }

    /*
     * Defensa transitoria:
     *
     * mientras el JWT conserve RUT,
     * debe coincidir con el registro.
     */
    if (rutApoderado !== tokenData.rut) {
      fireAndForgetAudit({
        req,

        event: "invalid_token",

        statusCode: 401,

        apoderadoId: tokenData.apoderado_id,

        extra: {
          where: "me",

          reason: "TOKEN_IDENTITY_MISMATCH",
        },
      });

      return reply.code(401).send({
        ok: false,

        message: "UNAUTHORIZED",
      });
    }

    return reply.send({
      ok: true,

      apoderado: {
        apoderado_id: Number(row.apoderado_id),

        rut_apoderado: rutApoderado,

        nombre_apoderado: nombreApoderado,

        estado_id: Number(row.estado_id),

        must_change_password: Number(row.must_change_password),

        last_login_at: row.last_login_at ?? null,

        created_at: row.created_at ?? null,

        updated_at: row.updated_at ?? null,
      },
    });
  });

  /* =======================================================
     CHANGE PASSWORD
  ======================================================= */

  app.post("/change-password", async (req, reply) => {
    const tokenData = getTokenOr401(req, reply);

    if (!tokenData) {
      fireAndForgetAudit({
        req,

        event: "access_denied",

        statusCode: 401,

        apoderadoId: null,

        extra: {
          where: "change-password",
        },
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

        extra: {
          where: "change-password",

          reason: "BAD_REQUEST",
        },
      });

      return reply.code(400).send({
        ok: false,

        message: "BAD_REQUEST",
      });
    }

    const db = getDb();

    const [rows] = await db.query<any[]>(
      `
            SELECT
              apoderado_id,
              password_hash,
              estado_id

            FROM apoderados_auth

            WHERE apoderado_id = ?

            LIMIT 1
          `,
      [tokenData.apoderado_id]
    );

    /*
     * Cuenta inexistente o inactiva:
     * mismo contrato externo.
     */
    if (!rows?.length || Number(rows[0]?.estado_id) !== 1) {
      fireAndForgetAudit({
        req,

        event: "access_denied",

        statusCode: 401,

        apoderadoId: tokenData.apoderado_id,

        extra: {
          where: "change-password",

          reason: "UNAUTHORIZED",
        },
      });

      return reply.code(401).send({
        ok: false,

        message: "UNAUTHORIZED",
      });
    }

    const ok = await withAuthSlot(async () => {
      try {
        return await argon2.verify(
          rows[0].password_hash,

          parsed.data.current_password
        );
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

        extra: {
          where: "change-password",

          reason: "INVALID_CURRENT_PASSWORD",
        },
      });

      return reply.code(401).send({
        ok: false,

        message: "INVALID_CURRENT_PASSWORD",
      });
    }

    /*
     * Nueva contraseña:
     *
     * sólo Argon2.
     * Nunca AES.
     */
    const newHash = await withAuthSlot(() =>
      argon2.hash(
        parsed.data.new_password,

        ARGON2_HASH_OPTS
      )
    );

    await db.query(
      `
          UPDATE apoderados_auth

          SET
            password_hash = ?,
            must_change_password = 0,
            updated_at = NOW()

          WHERE apoderado_id = ?
            AND estado_id = 1

          LIMIT 1
        `,
      [newHash, tokenData.apoderado_id]
    );

    fireAndForgetAudit({
      req,

      event: "refresh",

      statusCode: 200,

      apoderadoId: tokenData.apoderado_id,

      extra: {
        where: "change-password",

        ok: true,
      },
    });

    return reply.send({
      ok: true,
    });
  });
}
