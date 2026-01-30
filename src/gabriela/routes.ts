// src/gabriela/routes.ts
import { FastifyInstance } from "fastify";
import { ZodError } from "zod";
import * as validators from "./validators";
import * as services from "./services";

export default async function gabrielaRoutes(app: FastifyInstance) {
  // Helper: extraer user del hook global
  const getUser = (req: any) => req.user as any;

  // Helper de errores consistente
  const sendError = (reply: any, e: any) => {
    if (e instanceof ZodError) {
      return reply.code(400).send({
        ok: false,
        message: "Validación inválida",
        issues: e.issues,
      });
    }

    const status = Number(e?.statusCode) || 500;
    return reply.code(status).send({
      ok: false,
      message: e?.message || "Error interno",
    });
  };

  // POST /gabriela/casos
  app.post("/casos", async (req: any, reply: any) => {
    try {
      const input = validators.CrearCasoSchema.parse(req.body ?? {});
      const user = getUser(req);
      const out = await services.crearCaso(user, input);
      return reply.send(out);
    } catch (e: any) {
      return sendError(reply, e);
    }
  });

  // GET /gabriela/casos/:id
  app.get("/casos/:id", async (req: any, reply: any) => {
    try {
      const { id } = validators.IdParamSchema.parse(req.params ?? {});
      const user = getUser(req);
      const out = await services.obtenerCasoDetalle(user, id);
      return reply.send(out);
    } catch (e: any) {
      return sendError(reply, e);
    }
  });

  // POST /gabriela/examenes
  app.post("/examenes", async (req: any, reply: any) => {
    try {
      const input = validators.SubirExamenSchema.parse(req.body ?? {});
      const user = getUser(req);
      const out = await services.subirExamen(user, input);
      return reply.send(out);
    } catch (e: any) {
      return sendError(reply, e);
    }
  });

  // POST /gabriela/examenes/:id/procesar
  app.post("/examenes/:id/procesar", async (req: any, reply: any) => {
    try {
      const { id } = validators.ProcesarExamenParamSchema.parse(req.params ?? {});
      const user = getUser(req);
      const out = await services.procesarExamen(user, id);
      return reply.send(out);
    } catch (e: any) {
      return sendError(reply, e);
    }
  });

  // GET /gabriela/examenes/:id/resultados
  app.get("/examenes/:id/resultados", async (req: any, reply: any) => {
    try {
      const { id } = validators.IdParamSchema.parse(req.params ?? {});
      const user = getUser(req);
      const out = await services.obtenerResultados(user, id);
      return reply.send(out);
    } catch (e: any) {
      return sendError(reply, e);
    }
  });
}
