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
 * App identity (purga RAFC -> WELI)
 * ─────────────────────────────────────────────── */
const APP_NAME = "WELI";

// ✅ Identidad JWT (alineada con auth.ts / auth_apoderado.ts)
const JWT_ISSUER = String((CONFIG as any)?.JWT_ISSUER ?? process.env.JWT_ISSUER ?? "app").trim();
const JWT_AUDIENCE = String((CONFIG as any)?.JWT_AUDIENCE ?? process.env.JWT_AUDIENCE ?? "web").trim();

/* ───────────────────────────────────────────────
 * Crear instancia Fastify
 * ─────────────────────────────────────────────── */
const app = Fastify({
  logger: CONFIG.NODE_ENV === "production" ? { level: "warn" } : { level: "info" },
});

/* ───────────────────────────────────────────────
 * Bootstrap
 * ─────────────────────────────────────────────── */
async function bootstrap() {
  /* ───────── Middlewares base ───────── */
  await app.register(cors, {
    origin: CONFIG.NODE_ENV === "production" ? CONFIG.CORS_ORIGIN : true,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    allowedHeaders: ["Content-Type", "Authorization"],
  });

  await app.register(helmet, {
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'none'"],
        "base-uri": ["'none'"],
        "form-action": ["'none'"],
        "frame-ancestors": ["'none'"],
        "img-src": ["'self'", "data:"],
        "connect-src": ["'self'"],
      },
    },
    frameguard: { action: "deny" },
    hsts:
      CONFIG.NODE_ENV === "production"
        ? { maxAge: 15552000, includeSubDomains: true, preload: false }
        : false,
    noSniff: true,
    referrerPolicy: { policy: "no-referrer" },
    crossOriginResourcePolicy: { policy: "same-origin" },
    crossOriginOpenerPolicy: { policy: "same-origin" },
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

  /* ───────── Home / Health ───────── */
  const HTML_CT = "text/html; charset=UTF-8";
  const JSON_CT = "application/json; charset=UTF-8";

  const homeHtml = () => `<!doctype html>
<html>
  <head><meta charset="utf-8"><title>${APP_NAME} API</title></head>
  <body>
    <h1>${APP_NAME} — API</h1>
    <p>Status: online</p>
    <p>Environment: ${CONFIG.NODE_ENV}</p>
    <p>Timestamp: ${new Date().toISOString()}</p>
  </body>
</html>`;

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

  /* ───────── Favicon / robots ───────── */
  app.get("/favicon.ico", async (_req, reply) => reply.code(204).send());
  app.get("/robots.txt", async (_req, reply) =>
    reply.header("Content-Type", "text/plain; charset=UTF-8").send("User-agent: *\nDisallow:\n")
  );

  /* ───────── Swagger (solo en dev) ───────── */
  if (CONFIG.NODE_ENV !== "production") {
    await app.register(swagger, {
      openapi: {
        info: {
          title: `${APP_NAME} API`,
          description: `Backend Node/Fastify — ${APP_NAME}`,
          version: "1.0.0",
        },
        servers: [
          { url: `http://127.0.0.1:${CONFIG.PORT || 8000}`, description: "Local" },
          // Si aún no tienes dominio final, déjalo genérico
          { url: "https://example.com/api", description: "Producción" },
        ],
        components: {
          securitySchemes: {
            bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
          },
        },
        security: [{ bearerAuth: [] }],
      },
    });

    await app.register(swaggerUI, {
      routePrefix: "/docs",
      uiConfig: { docExpansion: "list", deepLinking: true },
    });
  }

  /* ───────── Inicializar BD ───────── */
  await initDb();

  /* ───────── Registrar Schemas globales ───────── */
  await registerSchemas(app);

  /* ───────── Autenticación global JWT ───────── */

  const PUBLIC = [
    /^\/$/i,
    /^\/api\/?$/i,

    /^\/health(?:\/.*)?$/i,
    /^\/api\/health(?:\/.*)?$/i,

    // Eventos públicos
    /^\/api\/eventos\/public(?:\/.*)?$/i,
    /^\/api\/eventos\/health(?:\/.*)?$/i,

    // Login panel
    /^\/auth\/login(?:\/.*)?$/i,
    /^\/api\/auth\/login(?:\/.*)?$/i,

    // Login apoderado
    /^\/auth-apoderado\/login(?:\/.*)?$/i,
    /^\/api\/auth-apoderado\/login(?:\/.*)?$/i,

    // Logout (si lo dejas público, ok; si no, quítalo del PUBLIC)
    /^\/auth\/logout(?:\/.*)?$/i,
    /^\/api\/auth\/logout(?:\/.*)?$/i,

    // Docs
    /^\/docs(?:\/.*)?$/i,
    /^\/swagger(?:\/.*)?$/i,

    // básicos
    /^\/favicon\.ico$/i,
    /^\/robots\.txt$/i,

    // Noticias públicas
    /^\/api\/noticias(?:\/.*)?$/i,
    /^\/noticias(?:\/.*)?$/i,
  ];

  app.addHook("onRequest", async (req, reply) => {
    if (req.method === "OPTIONS" || req.method === "HEAD") return;

    const path = req.url.split("?")[0];
    if (PUBLIC.some((rx) => rx.test(path))) return;

    const auth = req.headers.authorization;
    if (!auth?.startsWith("Bearer ")) {
      return reply.code(401).send({ ok: false, message: "Falta Bearer token" });
    }

    try {
      const token = auth.substring(7);

      // ✅ Alineado con auth.ts / auth_apoderado.ts
      const payload: any = jwt.verify(token, CONFIG.JWT_SECRET, {
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
      });

      // ✅ Apoderado
      if (payload?.type === "apoderado") {
        (req as any).user = {
          type: "apoderado",
          apoderado_id: Number(payload.apoderado_id),
          rut: String(payload.rut ?? ""),
        };
        return;
      }

      // ✅ Panel (admin/staff)
      (req as any).user = {
        type: "admin",
        id: Number(payload.sub),
        rol_id: Number(payload.rol_id),
        nombre_usuario: String(payload.nombre_usuario ?? ""),
      };
    } catch {
      return reply.code(401).send({ ok: false, message: "Token inválido o expirado" });
    }
  });

  /* ───────── Registrar rutas ───────── */
  await registerRoutes(app);

  /* ───────── Shutdown ───────── */
  const close = async () => {
    app.log.info("Shutting down gracefully...");
    try {
      await app.close();

      try {
        const pool = getDb();
        await pool.end();
        app.log.info("MySQL pool closed");
      } catch (e) {
        app.log.error(e, "Pool close error");
      }

      process.exit(0);
    } catch (err) {
      app.log.error({ err }, "Error during shutdown");
      process.exit(1);
    }
  };

  process.on("SIGINT", close);
  process.on("SIGTERM", close);

  /* ───────── Listen ───────── */
  const PORT = Number(process.env.PORT) || CONFIG.PORT || 8000;
  const HOST = "0.0.0.0";

  await app.listen({ port: PORT, host: HOST });
  app.log.info(`🟢 ${APP_NAME} API ready (env=${CONFIG.NODE_ENV}) — listening on ${HOST}:${PORT}`);
}

bootstrap().catch((err) => {
  app.log.error(err, "❌ Fatal error on bootstrap");
  process.exit(1);
});
