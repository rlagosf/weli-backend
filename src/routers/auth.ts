// src/routers/auth.ts

import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z } from "zod";

import { verify as argon2Verify, hash as argon2Hash } from "@node-rs/argon2";

import jwt, { SignOptions } from "jsonwebtoken";

import { db } from "../db";

import { CONFIG } from "../config";

import { requireAuth as authzRequireAuth, requireRoles as authzRequireRoles } from "../middlewares/authz";

import { blindIndex, decryptNullable, validateCryptoConfiguration } from "../services/crypto";

/* =========================================================
   CONFIGURACIÓN GENERAL
========================================================= */

/**
 * Roles admitidos dentro del panel WELI:
 *
 * 1 = administrador
 * 2 = staff
 * 3 = superadmin
 */
const ALLOWED_PANEL_ROLES = new Set([1, 2, 3]);

/**
 * Estado requerido para permitir login.
 */
const ACTIVE_ESTADO_ID = 1;

/**
 * Algoritmo JWT permitido.
 *
 * Se fija explícitamente para evitar aceptar
 * algoritmos diferentes durante la verificación.
 */
const JWT_ALGORITHM = "HS256" as const;

/**
 * Issuer y audience deben coincidir con authz.ts.
 */
const JWT_ISSUER = String((CONFIG as any)?.JWT_ISSUER ?? process.env.JWT_ISSUER ?? "app").trim();

const JWT_AUDIENCE = String((CONFIG as any)?.JWT_AUDIENCE ?? process.env.JWT_AUDIENCE ?? "web").trim();

/**
 * Logging opcional de rendimiento.
 *
 * IMPORTANTE:
 * este logging NO debe contener PII.
 */
const PERF_LOG = String((CONFIG as any)?.AUTH_PERF_LOG ?? process.env.AUTH_PERF_LOG ?? "0") === "1";

/**
 * Sólo debe activarse cuando WELI esté efectivamente
 * detrás de un proxy confiable.
 */
const TRUST_PROXY = String((CONFIG as any)?.TRUST_PROXY ?? process.env.TRUST_PROXY ?? "0") === "1";

/**
 * Limita verificaciones Argon2 concurrentes
 * para evitar saturar CPU.
 */
const MAX_AUTH_CONCURRENCY = Math.max(
  2,
  Number((CONFIG as any)?.AUTH_CONCURRENCY ?? process.env.AUTH_CONCURRENCY ?? 8) || 8
);

/**
 * Límite de longitud para auth_audit.extra.
 */
const AUDIT_EXTRA_MAX_CHARS = Math.max(
  512,
  Number((CONFIG as any)?.AUDIT_EXTRA_MAX_CHARS ?? process.env.AUDIT_EXTRA_MAX_CHARS ?? 2048) || 2048
);

/* =========================================================
   JWT SECRET
========================================================= */

/**
 * Obtiene la clave JWT.
 *
 * JWT_SECRET:
 * - firma tokens;
 * - NO es la clave AES;
 * - NO es la clave de blind indexes.
 */
function getJwtSecret() {
  const secret = String(CONFIG.JWT_SECRET ?? process.env.JWT_SECRET ?? "");

  if (!secret) {
    throw new Error("JWT_SECRET missing");
  }

  if (secret.length < 32) {
    throw new Error("JWT_SECRET must contain at least 32 characters");
  }

  return secret;
}

/* =========================================================
   EXPIRACIÓN JWT
========================================================= */

type ExpiresIn = SignOptions["expiresIn"];

/**
 * Normaliza JWT_EXPIRES_IN.
 *
 * Ejemplos válidos:
 *
 * 3600
 * 30m
 * 12h
 * 7d
 */
function normalizeExpiresIn(value: unknown): ExpiresIn {
  const FALLBACK: ExpiresIn = "12h";

  if (value == null) {
    return FALLBACK;
  }

  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return Math.floor(value);
  }

  const raw = String(value).trim();

  if (!raw) {
    return FALLBACK;
  }

  if (/^\d+$/.test(raw)) {
    const n = Number(raw);

    return Number.isFinite(n) && n > 0 ? Math.floor(n) : FALLBACK;
  }

  const compact = raw.replace(/\s+/g, "");

  if (/^\d+(ms|s|m|h|d|w|y)$/i.test(compact)) {
    return compact as ExpiresIn;
  }

  return FALLBACK;
}

/* =========================================================
   HELPERS DE IDENTIDAD CIFRADA
========================================================= */

/**
 * Normalización canónica utilizada para
 * nombre_usuario_idx.
 *
 * DEBE ser exactamente la misma utilizada
 * durante la migración y en usuarios.ts:
 *
 * - trim
 * - lowercase
 */
function normalizeUsernameForIndex(value: unknown): string {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

/**
 * Obtiene el blind index del username.
 *
 * No se utiliza cifrado determinístico.
 *
 * El índice es HMAC-SHA256 usando
 * WELI_DATA_INDEX_KEY.
 */
function usernameBlindIndex(nombreUsuario: string): string {
  const normalized = normalizeUsernameForIndex(nombreUsuario);

  if (!normalized) {
    throw new Error("INVALID_USERNAME");
  }

  return blindIndex(normalized);
}

/**
 * Descifra un campo textual obligatorio.
 *
 * Se utiliza para nombre_usuario después
 * de verificar correctamente la contraseña.
 */
function decryptRequiredText(encrypted: unknown, fieldName: string): string {
  if (encrypted === null || encrypted === undefined || String(encrypted).trim() === "") {
    throw new Error(`${fieldName}_ENCRYPTED_MISSING`);
  }

  const decrypted = decryptNullable(String(encrypted));

  if (decrypted === null || decrypted === undefined || String(decrypted).trim() === "") {
    throw new Error(`${fieldName}_DECRYPT_FAILED`);
  }

  return String(decrypted);
}

/**
 * Descifra un campo textual opcional.
 */
function decryptOptionalText(encrypted: unknown): string | null {
  if (encrypted === null || encrypted === undefined || String(encrypted).trim() === "") {
    return null;
  }

  const decrypted = decryptNullable(String(encrypted));

  return decrypted == null ? null : String(decrypted);
}

/* =========================================================
   AUDITORÍA
========================================================= */

type AuditEvent = "login" | "logout" | "refresh" | "invalid_token" | "access_denied";

/**
 * Obtiene IP respetando TRUST_PROXY.
 */
function getIp(req: FastifyRequest): string | null {
  if (!TRUST_PROXY) {
    return (req as any).ip ? String((req as any).ip) : null;
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

  return (req as any).ip ? String((req as any).ip) : null;
}

/**
 * Serializa audit.extra con límite.
 *
 * No debe recibir:
 *
 * - username;
 * - email;
 * - RUT;
 * - password;
 * - JWT;
 * - ciphertext.
 */
function safeJsonTruncate(extra: unknown, maxChars: number) {
  if (!extra) {
    return null;
  }

  try {
    const json = JSON.stringify(extra);

    return json.length <= maxChars ? json : json.slice(0, maxChars);
  } catch {
    return null;
  }
}

/**
 * Auditoría persistente.
 *
 * La auditoría jamás debe impedir
 * autenticación por un fallo propio.
 */
async function audit(event: AuditEvent, req: FastifyRequest, status: number, userId?: number | null, extra?: unknown) {
  try {
    const ip = getIp(req);

    const userAgent = (req.headers["user-agent"] as string) || null;

    const route = req.raw?.url || "";

    const method = req.method || "GET";

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
          extra
        )

        VALUES
        (
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          ?
        )
      `,
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
    /*
     * La auditoría nunca debe interrumpir
     * el flujo de autenticación.
     */
  }
}

/**
 * Auditoría no bloqueante.
 */
function fireAndForgetAudit(...args: Parameters<typeof audit>) {
  void audit(...args).catch(() => {});
}

/* =========================================================
   SEMÁFORO ARGON2
========================================================= */

/**
 * Argon2 consume CPU.
 *
 * Este semáforo limita la cantidad de
 * hashes/verificaciones concurrentes.
 */
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
   RATE LIMIT
========================================================= */

/**
 * Máximo de fallos dentro de ventana.
 */
const RL_MAX = 10;

/**
 * Ventana:
 * 10 minutos.
 */
const RL_WINDOW_MS = 10 * 60_000;

/**
 * Bloqueo:
 * 15 minutos.
 */
const RL_BLOCK_MS = 15 * 60_000;

/**
 * Protección del Map.
 */
const RL_MAX_KEYS = 50_000;

const RL_GC_INTERVAL_MS = 60_000;

type RLState = {
  count: number;

  windowStart: number;

  blockedUntil: number;

  lastSeen: number;
};

const rl = new Map<string, RLState>();

/**
 * El username se usa exclusivamente
 * dentro de memoria RAM para rate limiting.
 *
 * No se persiste.
 */
function rlKey(ip: string | null, nombreUsuario: string) {
  return `${ip || "noip"}:${normalizeUsernameForIndex(nombreUsuario)}`;
}

function rlFallbackKey(ip: string | null) {
  return `${ip || "noip"}:*`;
}

function rlSafeKeysOk() {
  return rl.size < RL_MAX_KEYS;
}

/**
 * Sólo consulta estado.
 *
 * NO incrementa contador.
 */
function checkRateLimit(ip: string | null, nombreUsuario: string) {
  const now = Date.now();

  const exactKey = rlKey(ip, nombreUsuario);

  const keys = [exactKey, rlFallbackKey(ip)];

  for (const key of keys) {
    const state = rl.get(key);

    if (!state) {
      continue;
    }

    state.lastSeen = now;

    if (state.blockedUntil > now) {
      return {
        ok: false,

        retryAfterSec: Math.ceil((state.blockedUntil - now) / 1000),
      };
    }

    if (now - state.windowStart > RL_WINDOW_MS) {
      rl.delete(key);
    }
  }

  return {
    ok: true,

    retryAfterSec: 0,
  };
}

/**
 * Único lugar donde se suma
 * un fallo real.
 */
function registerFailed(ip: string | null, nombreUsuario: string) {
  const now = Date.now();

  const key = rlSafeKeysOk() ? rlKey(ip, nombreUsuario) : rlFallbackKey(ip);

  const state =
    rl.get(key) ??
    ({
      count: 0,

      windowStart: now,

      blockedUntil: 0,

      lastSeen: now,
    } satisfies RLState);

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
    state.blockedUntil = now + RL_BLOCK_MS;

    state.count = 0;

    state.windowStart = now;
  }

  rl.set(key, state);
}

/**
 * Login correcto:
 *
 * elimina penalización previa del
 * username/IP.
 */
function clearRateLimit(ip: string | null, nombreUsuario: string) {
  rl.delete(rlKey(ip, nombreUsuario));

  /*
   * También limpiamos posible fallback IP:*
   * creado cuando RL_MAX_KEYS estaba lleno.
   */
  rl.delete(rlFallbackKey(ip));
}

/* =========================================================
   GARBAGE COLLECTOR RATE LIMIT
========================================================= */

let rlGcStarted = false;

function startRlGcOnce() {
  if (rlGcStarted) {
    return;
  }

  rlGcStarted = true;

  setInterval(() => {
    const now = Date.now();

    for (const [key, state] of rl.entries()) {
      /*
       * Una hora sin actividad.
       */
      if (now - state.lastSeen > 60 * 60_000) {
        rl.delete(key);

        continue;
      }

      /*
       * Bloqueo expirado.
       */
      if (state.blockedUntil > 0 && state.blockedUntil <= now) {
        rl.delete(key);

        continue;
      }

      /*
       * Ventana antigua.
       */
      if (state.blockedUntil === 0 && now - state.windowStart > 2 * RL_WINDOW_MS) {
        rl.delete(key);
      }
    }
  }, RL_GC_INTERVAL_MS).unref?.();
}

/* =========================================================
   ANTI-TIMING
========================================================= */

/**
 * Si el usuario no existe igualmente
 * verificamos un hash Argon2.
 *
 * Esto reduce diferencias temporales
 * entre:
 *
 * - usuario inexistente;
 * - contraseña incorrecta.
 */
const DUMMY_HASH_PROMISE = withAuthSlot(() => argon2Hash("weli-dummy-password-not-valid"));

/* =========================================================
   SCHEMAS
========================================================= */

const LoginSchema = z
  .object({
    nombre_usuario: z.string().trim().min(3).max(80),

    password: z.string().min(4).max(200),

    /*
     * Este valor NO determina tenant.
     *
     * Para Admin/Staff sólo sirve como
     * validación de consistencia.
     */
    academia_id: z.coerce.number().int().positive().optional(),
  })
  .strict();

/* =========================================================
   ROUTER
========================================================= */

export default async function auth(app: FastifyInstance) {
  /* =======================================================
     VALIDACIÓN CRIPTOGRÁFICA
  ======================================================= */

  /**
   * Fail-fast.
   *
   * Este login depende de:
   *
   * WELI_DATA_ENCRYPTION_KEY
   * WELI_DATA_INDEX_KEY
   *
   * Si falta alguna, no permitimos que
   * el router opere parcialmente.
   */
  validateCryptoConfiguration();

  startRlGcOnce();

  /* =======================================================
     HEALTH
  ======================================================= */

  app.get("/health", async () => ({
    module: "auth",

    status: "ready",

    timestamp: new Date().toISOString(),
  }));

  /* =======================================================
     LOGIN PANEL
  ======================================================= */

  app.post(
    "/login",

    {
      schema: {
        security: [],
      },
    },

    async (
      req: FastifyRequest,

      reply: FastifyReply
    ) => {
      /* ---------------------------------------------------
         1. VALIDACIÓN DEL PAYLOAD
      --------------------------------------------------- */

      const parsed = LoginSchema.safeParse(req.body);

      if (!parsed.success) {
        fireAndForgetAudit(
          "access_denied",

          req,

          400,

          null,

          {
            reason: "invalid_payload",
          }
        );

        return reply.code(400).send({
          ok: false,

          message: "Payload inválido",
        });
      }

      /* ---------------------------------------------------
         2. NORMALIZACIÓN ENTRADA
      --------------------------------------------------- */

      const ip = getIp(req);

      const nombreUsuario = parsed.data.nombre_usuario.trim();

      const password = parsed.data.password;

      const academiaIdInput = parsed.data.academia_id === undefined ? undefined : Number(parsed.data.academia_id);

      /* ---------------------------------------------------
         3. RATE LIMIT
      --------------------------------------------------- */

      const rlCheck = checkRateLimit(ip, nombreUsuario);

      if (!rlCheck.ok) {
        /*
         * Deliberadamente NO persistimos
         * nombre_usuario en auth_audit.
         */
        fireAndForgetAudit(
          "access_denied",

          req,

          429,

          null,

          {
            reason: "rate_limit",

            retryAfterSec: rlCheck.retryAfterSec,
          }
        );

        reply.header(
          "Retry-After",

          String(rlCheck.retryAfterSec)
        );

        return reply.code(429).send({
          ok: false,

          message: "TOO_MANY_ATTEMPTS",
        });
      }

      const t0 = Date.now();

      try {
        /* -------------------------------------------------
           4. BLIND INDEX DEL USERNAME
        ------------------------------------------------- */

        /**
         * El login ya NO busca por:
         *
         * nombre_usuario = BINARY ?
         *
         * Ahora utiliza:
         *
         * nombre_usuario_idx = ?
         */
        const nombreUsuarioIdx = usernameBlindIndex(nombreUsuario);

        /* -------------------------------------------------
           5. CONSULTA DE USUARIO
        ------------------------------------------------- */

        /**
         * No seleccionamos PII plaintext.
         *
         * Obtenemos:
         *
         * nombre_usuario_enc
         * email_enc
         *
         * password sigue siendo hash Argon2.
         */
        const [rows]: any = await db.query(
          `
              SELECT
                id,

                nombre_usuario_enc,

                email_enc,

                password,

                rol_id,

                estado_id,

                academia_id

              FROM usuarios

              WHERE nombre_usuario_idx = ?

                AND estado_id = ?

                AND rol_id IN (1,2,3)

              LIMIT 1
            `,
          [nombreUsuarioIdx, ACTIVE_ESTADO_ID]
        );

        const t1 = Date.now();

        const user = rows?.length ? rows[0] : null;

        /* -------------------------------------------------
           6. VERIFICACIÓN ARGON2
        ------------------------------------------------- */

        /**
         * Si el usuario no existe igualmente se usa
         * DUMMY_HASH_PROMISE.
         *
         * NO eliminar.
         */
        const hashToVerify = user?.password ?? (await DUMMY_HASH_PROMISE);

        const t2a = Date.now();

        const passwordOk = await withAuthSlot(async () => {
          try {
            return await argon2Verify(
              hashToVerify,

              password
            );
          } catch {
            return false;
          }
        });

        const t2b = Date.now();

        /* -------------------------------------------------
           7. PERFORMANCE LOG SIN PII
        ------------------------------------------------- */

        if (PERF_LOG) {
          req.log.info(
            {
              /*
               * NO:
               * nombre_usuario
               * email
               * password
               * ciphertext
               */

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

        /* -------------------------------------------------
           8. CREDENCIALES INVÁLIDAS
        ------------------------------------------------- */

        if (!user || !passwordOk) {
          registerFailed(
            ip,

            nombreUsuario
          );

          /*
           * No persistimos el username.
           */
          fireAndForgetAudit(
            "access_denied",

            req,

            401,

            user?.id ?? null,

            {
              reason: !user ? "user_not_found_or_not_allowed" : "bad_password",

              ms_total: t2b - t0,
            }
          );

          return reply.code(401).send({
            ok: false,

            message: "Credenciales inválidas",
          });
        }

        /* -------------------------------------------------
           9. DESCIFRADO AUTORIZADO
        ------------------------------------------------- */

        /**
         * IMPORTANTE:
         *
         * Sólo llegamos aquí después de:
         *
         * - encontrar usuario mediante blind index;
         * - verificar password correctamente.
         *
         * Recién ahora desciframos PII.
         */
        let nombreUsuarioReal: string;

        let emailReal: string | null;

        try {
          nombreUsuarioReal = decryptRequiredText(
            user.nombre_usuario_enc,

            "NOMBRE_USUARIO"
          );

          emailReal = decryptOptionalText(user.email_enc);
        } catch (error: any) {
          /*
           * Nunca registramos:
           *
           * ciphertext;
           * plaintext;
           * password.
           */
          req.log.error(
            {
              user_id: Number(user.id),

              message: error?.message,
            },

            "[auth/login] encrypted user data unavailable"
          );

          fireAndForgetAudit(
            "access_denied",

            req,

            500,

            Number(user.id),

            {
              reason: "encrypted_user_data_unavailable",
            }
          );

          return reply.code(500).send({
            ok: false,

            message: "Error procesando login",
          });
        }

        /* -------------------------------------------------
           10. DATOS OPERACIONALES
        ------------------------------------------------- */

        const rol = Number(user.rol_id);

        const estado = Number(user.estado_id);

        const academiaIdDb = user.academia_id === null ? null : Number(user.academia_id);

        /* -------------------------------------------------
           11. VALIDACIÓN DE ROL
        ------------------------------------------------- */

        if (!ALLOWED_PANEL_ROLES.has(rol)) {
          fireAndForgetAudit(
            "access_denied",

            req,

            403,

            user.id,

            {
              reason: "role_not_allowed",

              rol_id: rol,
            }
          );

          return reply.code(403).send({
            ok: false,

            message: "No autorizado",
          });
        }

        /* -------------------------------------------------
           12. MULTI-TENANT
        ------------------------------------------------- */

        let academiaIdEffective: number | null = null;

        if (rol === 3) {
          /*
           * SUPERADMIN
           *
           * No queda asociado a un tenant
           * dentro del JWT.
           *
           * Los routers tenantizados exigirán
           * posteriormente x-academia-id.
           */
          academiaIdEffective = null;
        } else {
          /*
           * ADMIN / STAFF
           *
           * La academia real viene exclusivamente
           * desde la BD.
           */
          if (academiaIdDb === null || !Number.isFinite(academiaIdDb) || academiaIdDb <= 0) {
            fireAndForgetAudit(
              "access_denied",

              req,

              400,

              user.id,

              {
                reason: "user_missing_academia_id_db",

                rol_id: rol,
              }
            );

            return reply.code(400).send({
              ok: false,

              message: "Usuario sin academia asignada. Contacta al administrador.",
            });
          }

          /*
           * Si frontend envía academia_id,
           * NO determina tenant.
           *
           * Sólo se utiliza para detectar
           * inconsistencias.
           */
          if (academiaIdInput !== undefined && academiaIdDb !== academiaIdInput) {
            fireAndForgetAudit(
              "access_denied",

              req,

              401,

              user.id,

              {
                reason: "academy_mismatch",

                rol_id: rol,

                academia_id_input: academiaIdInput,

                academia_id_db: academiaIdDb,
              }
            );

            return reply.code(401).send({
              ok: false,

              message: "Credenciales inválidas",
            });
          }

          academiaIdEffective = academiaIdDb;
        }

        /* -------------------------------------------------
           13. LOGIN CORRECTO / RATE LIMIT
        ------------------------------------------------- */

        clearRateLimit(
          ip,

          nombreUsuario
        );

        /* -------------------------------------------------
           14. JWT WELI
        ------------------------------------------------- */

        const userIdStr = String(user.id);

        /**
         * Se mantiene la estructura existente:
         *
         * claims top-level
         * +
         * objeto user
         *
         * Esto evita romper frontend y routers
         * existentes.
         *
         * nombre_usuario se incorpora descifrado
         * sólo después de autenticar.
         */
        const payload = {
          type: "admin",

          sub: userIdStr,

          rol_id: rol,

          nombre_usuario: nombreUsuarioReal,

          academia_id: academiaIdEffective,

          user: {
            type: "admin",

            id: Number(user.id),

            rol_id: rol,

            nombre_usuario: nombreUsuarioReal,

            academia_id: academiaIdEffective,
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
          token = jwt.sign(
            payload,

            getJwtSecret(),

            signOpts
          );
        } catch (error: any) {
          /*
           * No imprimimos payload completo.
           *
           * Podría contener nombre de usuario.
           */
          req.log.error(
            {
              user_id: Number(user.id),

              message: error?.message,

              code: error?.code,

              issuer: JWT_ISSUER,

              audience: JWT_AUDIENCE,

              algorithm: JWT_ALGORITHM,

              expiresIn: signOpts.expiresIn,
            },

            "[auth/login] jwt.sign failed"
          );

          fireAndForgetAudit(
            "access_denied",

            req,

            500,

            user.id,

            {
              reason: "jwt_sign_failed",
            }
          );

          return reply.code(500).send({
            ok: false,

            message: "Error procesando login",
          });
        }

        /* -------------------------------------------------
           15. AUDITORÍA LOGIN CORRECTO
        ------------------------------------------------- */

        fireAndForgetAudit(
          "login",

          req,

          200,

          user.id,

          {
            ok: true,

            rol_id: rol,

            /*
             * IDs operacionales permitidos.
             */
            academia_id: academiaIdEffective,
          }
        );

        /* -------------------------------------------------
           16. RESPUESTA PÚBLICA
        ------------------------------------------------- */

        /**
         * El frontend conserva exactamente
         * el contrato anterior.
         *
         * Nunca salen:
         *
         * nombre_usuario_enc
         * nombre_usuario_idx
         * email_enc
         * email_idx
         * password
         */
        return reply.send({
          ok: true,

          token,

          rol_id: rol,

          user: {
            id: Number(user.id),

            nombre_usuario: nombreUsuarioReal,

            email: emailReal,

            rol_id: rol,

            estado_id: estado,

            academia_id: academiaIdEffective,
          },
        });
      } catch (error: any) {
        /*
         * Error inesperado.
         *
         * Deliberadamente no registramos
         * req.body ni el error completo,
         * porque podrían contener PII.
         */
        req.log.error(
          {
            message: error?.message,

            code: error?.code,
          },

          "auth/login failed"
        );

        fireAndForgetAudit(
          "access_denied",

          req,

          500,

          null,

          {
            reason: "exception",
          }
        );

        return reply.code(500).send({
          ok: false,

          message: "Error procesando login",
        });
      }
    }
  );

  /* =======================================================
     LOGOUT PANEL
  ======================================================= */

  app.post(
    "/logout",

    {
      preHandler: [authzRequireAuth, authzRequireRoles([1, 2, 3])],
    },

    async (
      req: FastifyRequest,

      reply: FastifyReply
    ) => {
      /*
       * requireAuth ya construyó
       * req.auth de forma verificada.
       */
      const auth = (req as any).auth;

      const userId = auth?.type === "user" ? (auth?.user_id ?? null) : null;

      /*
       * user_id no es PII sensible y puede
       * utilizarse como identificador técnico
       * en auditoría.
       */
      fireAndForgetAudit(
        "logout",

        req,

        200,

        userId
      );

      return reply.send({
        ok: true,

        message: "logout",
      });
    }
  );
}
