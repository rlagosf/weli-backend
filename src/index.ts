// src/index.ts

import Fastify from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import jwt from "jsonwebtoken";
import swagger from "@fastify/swagger";
import swaggerUI from "@fastify/swagger-ui";

import { CONFIG } from "./config";
import { initDb, getDb } from "./db";
import { registerRoutes } from "./routes";
import { registerSchemas } from "./schemas/schemas";

/* ───────────────────────────────────────────────
 * App identity
 * ─────────────────────────────────────────────── */

const APP_NAME = "WELI";

/*
 * Identidad JWT.
 * Debe mantenerse alineada con:
 *
 * - routers/auth.ts
 * - routers/auth_apoderado.ts
 * - middlewares/authz.ts
 */
const JWT_ISSUER = String((CONFIG as any)?.JWT_ISSUER ?? process.env.JWT_ISSUER ?? "app").trim();

const JWT_AUDIENCE = String((CONFIG as any)?.JWT_AUDIENCE ?? process.env.JWT_AUDIENCE ?? "web").trim();

const PANEL_ROLES = new Set([1, 2, 3]);

/* ───────────────────────────────────────────────
 * Fastify
 * ─────────────────────────────────────────────── */

const app = Fastify({
  logger: CONFIG.NODE_ENV === "production" ? { level: "warn" } : { level: "info" },
});

/* ───────────────────────────────────────────────
 * Helpers
 * ─────────────────────────────────────────────── */

function toNumberOrUndef(value: unknown): number | undefined {
  if (value === null || value === undefined || value === "") {
    return undefined;
  }

  const parsed = Number(value);

  return Number.isFinite(parsed) ? parsed : undefined;
}

function toPositiveIntOrUndef(value: unknown): number | undefined {
  const parsed = toNumberOrUndef(value);

  if (parsed === undefined || !Number.isInteger(parsed) || parsed <= 0) {
    return undefined;
  }

  return parsed;
}

/* ───────────────────────────────────────────────
 * Bootstrap
 * ─────────────────────────────────────────────── */

async function bootstrap() {
  /* =======================================================
     CORS
  ======================================================= */

  const envAllowed = String(process.env.CORS_ALLOWED_HEADERS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  /*
   * x-academia-id es necesario para Superadmin.
   *
   * Admin/Staff NO obtienen su tenant desde este header:
   * getEffectiveAcademiaId() utiliza la academia firmada
   * en su JWT.
   */
  const BASE_ALLOWED_HEADERS = [
    "Content-Type",
    "Authorization",
    "Accept",
    "Cache-Control",
    "Pragma",
    "Expires",
    "x-academia-id",
  ];

  const allowedHeaders = Array.from(new Set([...BASE_ALLOWED_HEADERS, ...envAllowed]));

  await app.register(cors, {
    origin: CONFIG.NODE_ENV === "production" ? CONFIG.CORS_ORIGIN : true,

    credentials: true,

    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],

    allowedHeaders,

    exposedHeaders: ["Content-Length", "Content-Type", "Cache-Control"],

    maxAge: 86400,
  });

  /* =======================================================
     SECURITY HEADERS
  ======================================================= */

  await app.register(helmet, {
    contentSecurityPolicy:
      CONFIG.NODE_ENV === "production"
        ? {
            useDefaults: true,

            directives: {
              "default-src": ["'none'"],
              "base-uri": ["'none'"],
              "form-action": ["'none'"],
              "frame-ancestors": ["'none'"],

              "img-src": ["'self'", "data:"],

              "connect-src": [
                "'self'",

                ...(CONFIG.CORS_ORIGIN
                  ? Array.isArray(CONFIG.CORS_ORIGIN)
                    ? CONFIG.CORS_ORIGIN
                    : [String(CONFIG.CORS_ORIGIN)]
                  : []),
              ],
            },
          }
        : false,

    frameguard: {
      action: "deny",
    },

    hsts:
      CONFIG.NODE_ENV === "production"
        ? {
            maxAge: 15552000,
            includeSubDomains: true,
            preload: false,
          }
        : false,

    noSniff: true,

    referrerPolicy: {
      policy: "no-referrer",
    },

    crossOriginResourcePolicy: {
      policy: "same-origin",
    },

    crossOriginOpenerPolicy: {
      policy: "same-origin",
    },
  });

  app.addHook("onSend", async (_req, reply, payload) => {
    reply.header(
      "Permissions-Policy",
      "geolocation=(), camera=(), microphone=(), payment=(), usb=(), fullscreen=(self)"
    );

    reply.header("X-DNS-Prefetch-Control", "off");

    reply.header("X-Permitted-Cross-Domain-Policies", "none");

    return payload;
  });

  /* =======================================================
     SCHEMAS GLOBALES
  ======================================================= */

  /*
   * Se registran ANTES de Swagger y antes de las rutas.
   *
   * Esto permite reutilizar posteriormente:
   *
   * $ref: "PlanListResponse#"
   * $ref: "ErrorResponse#"
   * $ref: "UnauthorizedResponse#"
   * etc.
   */
  await registerSchemas(app);

  /* =======================================================
     HOME / HEALTH
  ======================================================= */

  const HTML_CT = "text/html; charset=UTF-8";

  const JSON_CT = "application/json; charset=UTF-8";

  const homeHtml = () => `
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>${APP_NAME} API</title>
  </head>

  <body>
    <h1>${APP_NAME} — API</h1>
    <p>Status: online</p>
    <p>Environment: ${CONFIG.NODE_ENV}</p>
    <p>Timestamp: ${new Date().toISOString()}</p>
  </body>
</html>
`;

  const healthJson = (req: any) => ({
    ok: true,
    app: APP_NAME,
    env: CONFIG.NODE_ENV,
    path: req.url,
    time: new Date().toISOString(),
  });

  app.get("/", async (_req, reply) => reply.header("Content-Type", HTML_CT).send(homeHtml()));

  app.get("/api", async (_req, reply) => reply.header("Content-Type", HTML_CT).send(homeHtml()));

  app.get("/health", async (req, reply) => reply.header("Content-Type", JSON_CT).send(healthJson(req)));

  app.get("/api/health", async (req, reply) => reply.header("Content-Type", JSON_CT).send(healthJson(req)));

  /* =======================================================
     FAVICON / ROBOTS
  ======================================================= */

  app.get("/favicon.ico", async (_req, reply) => reply.code(204).send());

  app.get("/robots.txt", async (_req, reply) =>
    reply.header("Content-Type", "text/plain; charset=UTF-8").send("User-agent: *\nDisallow:\n")
  );

  /* =======================================================
     SWAGGER
     SOLO DESARROLLO
  ======================================================= */

  if (CONFIG.NODE_ENV !== "production") {
    await app.register(swagger, {
      openapi: {
        info: {
          title: `${APP_NAME} API`,
          description: `Backend Node/Fastify — ${APP_NAME}`,
          version: "1.0.0",
        },

        servers: [
          {
            url: `http://127.0.0.1:${CONFIG.PORT || 8000}`,
            description: "Local",
          },
        ],

        components: {
          securitySchemes: {
            bearerAuth: {
              type: "http",
              scheme: "bearer",
              bearerFormat: "JWT",
            },

            /*
             * Header utilizado solamente para seleccionar
             * academia efectiva cuando el token pertenece
             * a Superadmin.
             */
            academiaHeader: {
              type: "apiKey",
              in: "header",
              name: "x-academia-id",
            },
          },
        },
      },
    });

    await app.register(swaggerUI, {
      routePrefix: "/docs",

      uiConfig: {
        docExpansion: "list",
        deepLinking: true,
      },
    });
  }

  /* =======================================================
     DATABASE
  ======================================================= */

  await initDb();

  /* =======================================================
     ENDPOINTS PÚBLICOS
  ======================================================= */

  const PUBLIC = [
    /^\/$/i,
    /^\/api\/?$/i,

    /^\/health$/i,
    /^\/api\/health$/i,

    /*
     * Login panel.
     */
    /^\/auth\/login\/?$/i,
    /^\/api\/auth\/login\/?$/i,

    /*
     * Login apoderado.
     */
    /^\/auth-apoderado\/login\/?$/i,
    /^\/api\/auth-apoderado\/login\/?$/i,

    /*
     * Logout stateless.
     */
    /^\/auth\/logout\/?$/i,
    /^\/api\/auth\/logout\/?$/i,

    /*
     * Eventos explícitamente públicos.
     */
    /^\/api\/eventos\/public(?:\/.*)?$/i,

    /*
     * Noticias públicas.
     */
    /^\/api\/noticias(?:\/.*)?$/i,
    /^\/noticias(?:\/.*)?$/i,

    /*
     * Swagger solamente existe en desarrollo.
     */
    /^\/docs(?:\/.*)?$/i,
    /^\/swagger(?:\/.*)?$/i,

    /^\/favicon\.ico$/i,
    /^\/robots\.txt$/i,
  ];

  /* =======================================================
     AUTENTICACIÓN GLOBAL
  ======================================================= */

  /*
   * IMPORTANTE:
   *
   * Este hook únicamente establece identidad.
   *
   * NO reemplaza:
   *
   * requireAuth
   * requireRoles(...)
   * getEffectiveAcademiaId(...)
   *
   * La autorización fina continúa perteneciendo
   * a cada router.
   */
  app.addHook("onRequest", async (req, reply) => {
    /*
     * CORS preflight.
     */
    if (req.method === "OPTIONS" || req.method === "HEAD") {
      return;
    }

    const path = req.url.split("?")[0];

    if (PUBLIC.some((rx) => rx.test(path))) {
      return;
    }

    const authorization = req.headers.authorization;

    if (!authorization || !authorization.startsWith("Bearer ")) {
      return reply.code(401).send({
        ok: false,
        message: "Falta Bearer token",
      });
    }

    try {
      const token = authorization.substring(7).trim();

      if (!token) {
        return reply.code(401).send({
          ok: false,
          message: "Falta Bearer token",
        });
      }

      /*
       * Verificación criptográfica.
       *
       * Debe coincidir con auth.ts/authz.ts.
       */
      const payload: any = jwt.verify(token, CONFIG.JWT_SECRET, {
        algorithms: ["HS256"],
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
      });

      /* =================================================
           APODERADO
        ================================================= */

      if (payload?.type === "apoderado") {
        const apoderadoId = toPositiveIntOrUndef(payload?.apoderado_id);

        const rut = String(payload?.rut ?? "").trim();

        if (!apoderadoId || !rut) {
          return reply.code(401).send({
            ok: false,
            message: "Token inválido o expirado",
          });
        }

        const authObj = {
          type: "apoderado" as const,

          apoderado_id: apoderadoId,

          rut,
        };

        /*
         * Estándar actual.
         */
        (req as any).auth = authObj;

        /*
         * Compatibilidad temporal con
         * routers antiguos.
         */
        (req as any).user = authObj;

        return;
      }

      /* =================================================
           PANEL
           ADMIN / STAFF / SUPERADMIN
        ================================================= */

      const userId = toPositiveIntOrUndef(payload?.sub);

      const rolId = toPositiveIntOrUndef(payload?.rol_id);

      const academiaId = toPositiveIntOrUndef(payload?.academia_id);

      /*
       * Debe existir usuario y rol válido.
       */
      if (!userId || !rolId || !PANEL_ROLES.has(rolId)) {
        return reply.code(401).send({
          ok: false,
          message: "Token inválido o expirado",
        });
      }

      /*
       * ADMIN y STAFF necesitan academia
       * firmada obligatoriamente.
       *
       * SUPERADMIN puede no llevar academia,
       * porque la selecciona posteriormente
       * mediante x-academia-id.
       */
      if ((rolId === 1 || rolId === 2) && !academiaId) {
        return reply.code(401).send({
          ok: false,
          message: "Token sin academia válida",
        });
      }

      const authObj = {
        type: "user" as const,

        user_id: userId,
        rol_id: rolId,

        nombre_usuario: String(payload?.nombre_usuario ?? ""),

        academia_id: academiaId,
      };

      /*
       * Estándar actual.
       */
      (req as any).auth = authObj;

      /*
       * Compatibilidad temporal.
       *
       * No eliminar todavía mientras existan
       * routers antiguos utilizando req.user.
       */
      (req as any).user = {
        type: "admin",

        id: authObj.user_id,

        rol_id: authObj.rol_id,

        nombre_usuario: authObj.nombre_usuario,

        academia_id: authObj.academia_id ?? null,
      };
    } catch {
      return reply.code(401).send({
        ok: false,
        message: "Token inválido o expirado",
      });
    }
  });

  /* =======================================================
     ROUTES
  ======================================================= */

  /*
   * Las reglas específicas continúan dentro
   * de los routers:
   *
   * requireAuth
   * requireRoles
   * getEffectiveAcademiaId
   */
  await registerRoutes(app);

  /* =======================================================
     SHUTDOWN
  ======================================================= */

  let shuttingDown = false;

  const close = async () => {
    /*
     * Evita ejecutar el shutdown dos veces
     * si SIGINT y SIGTERM llegan juntos.
     */
    if (shuttingDown) {
      return;
    }

    shuttingDown = true;

    app.log.info("Shutting down gracefully...");

    try {
      await app.close();

      try {
        const pool = getDb();

        await pool.end();

        app.log.info("MySQL pool closed");
      } catch (error) {
        app.log.error(error, "Pool close error");
      }

      process.exit(0);
    } catch (err) {
      app.log.error({ err }, "Error during shutdown");

      process.exit(1);
    }
  };

  process.once("SIGINT", close);

  process.once("SIGTERM", close);

  /* =======================================================
     LISTEN
  ======================================================= */

  const PORT = Number(process.env.PORT) || CONFIG.PORT || 8000;

  const HOST = "0.0.0.0";

  await app.listen({
    port: PORT,
    host: HOST,
  });

  app.log.info(`🟢 ${APP_NAME} API ready (env=${CONFIG.NODE_ENV}) — listening on ${HOST}:${PORT}`);
}

/* ───────────────────────────────────────────────
 * Bootstrap fatal error
 * ─────────────────────────────────────────────── */

bootstrap().catch((err) => {
  app.log.error(err, "❌ Fatal error on bootstrap");

  process.exit(1);
});
