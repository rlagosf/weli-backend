// src/routers/establec_educ.ts
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: establec_educ
 * Campos: id (PK), nombre (VARCHAR UNIQUE)
 * Scope: catálogo global (sin academia)
 */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(3, "Debe tener al menos 3 caracteres"),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z.string().trim().min(3, "Debe tener al menos 3 caracteres").optional(),
  })
  .strict();

function normalize(row: any) {
  return {
    id: Number(row.id),
    nombre: String(row.nombre ?? ""),
  };
}

export default async function establec_educ(app: FastifyInstance) {
  // ✅ Catálogo:
  // - READ: roles 1/2/3
  // - WRITE: roles 1 y 3
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  // ─────────────────────────── Health ───────────────────────────
  app.get("/health", { preHandler: canRead }, async () => ({
    module: "establec_educ",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // ─────────────────────────── GET all ───────────────────────────
  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM establec_educ ORDER BY nombre ASC");
      reply.header("Cache-Control", "no-store");
      return reply.send({
        ok: true,
        count: rows?.length ?? 0,
        items: (rows || []).map(normalize),
      });
    } catch (err: any) {
      req.log.error({ err }, "establec_educ: error listando establecimientos");
      return reply.code(500).send({
        ok: false,
        message: "Error al listar establecimientos",
        error: err?.message,
      });
    }
  });

  // ─────────────────────────── GET /:id/ (trailing slash) ───────────────────────────
  app.get("/:id/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });
    return reply.redirect(`../${parsed.data.id}`);
  });

  // ─────────────────────────── GET by ID ───────────────────────────
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsed.data.id;

    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM establec_educ WHERE id = ? LIMIT 1", [id]);
      reply.header("Cache-Control", "no-store");

      if (!rows?.length) {
        return reply.code(404).send({ ok: false, message: "Establecimiento no encontrado" });
      }

      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      req.log.error({ err, id }, "establec_educ: error obteniendo establecimiento por id");
      return reply.code(500).send({
        ok: false,
        message: "Error al obtener establecimiento",
        error: err?.message,
      });
    }
  });

  // ─────────────────────────── POST ───────────────────────────
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const parsed = CreateSchema.parse(req.body);
      const nombre = parsed.nombre.trim();

      const [result]: any = await db.query("INSERT INTO establec_educ (nombre) VALUES (?)", [nombre]);

      reply.header("Cache-Control", "no-store");
      return reply.code(201).send({ ok: true, id: result.insertId, nombre });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const issues = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: issues });
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "El establecimiento ya existe" });
      }

      req.log.error({ err }, "establec_educ: error creando establecimiento");
      return reply.code(500).send({
        ok: false,
        message: "Error al crear establecimiento",
        error: err?.message,
      });
    }
  });

  // ─────────────────────────── PUT ───────────────────────────
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsedId = IdParam.safeParse(req.params);
    if (!parsedId.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsedId.data.id;

    try {
      const parsedBody = UpdateSchema.parse(req.body);
      if (Object.keys(parsedBody).length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const setClauses: string[] = [];
      const values: any[] = [];

      let updatedNombre: string | undefined;

      if (parsedBody.nombre !== undefined) {
        updatedNombre = parsedBody.nombre.trim();
        setClauses.push("nombre = ?");
        values.push(updatedNombre);
      }

      if (!setClauses.length) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      values.push(id);

      const [result]: any = await db.query(
        `UPDATE establec_educ SET ${setClauses.join(", ")} WHERE id = ? LIMIT 1`,
        values
      );

      reply.header("Cache-Control", "no-store");

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({
        ok: true,
        updated: { id, ...(updatedNombre !== undefined ? { nombre: updatedNombre } : {}) },
      });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const issues = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: issues });
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "El establecimiento ya existe" });
      }

      req.log.error({ err, id }, "establec_educ: error actualizando establecimiento");
      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar establecimiento",
        error: err?.message,
      });
    }
  });

  // ─────────────────────────── DELETE ───────────────────────────
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsed.data.id;

    try {
      const [result]: any = await db.query("DELETE FROM establec_educ WHERE id = ? LIMIT 1", [id]);

      reply.header("Cache-Control", "no-store");

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      req.log.error({ err, id }, "establec_educ: error eliminando establecimiento");
      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar establecimiento",
        error: err?.message,
      });
    }
  });
}
