// src/routers/estado_noticias.ts
import type { FastifyInstance, FastifyPluginOptions } from "fastify";
import { z } from "zod";
import { getDb } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(1, "nombre requerido").max(100, "máx 100 caracteres"),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z
      .string()
      .trim()
      .min(1, "nombre requerido")
      .max(100, "máx 100 caracteres")
      .optional(),
  })
  .strict();

export default async function estado_noticias(
  app: FastifyInstance,
  _opts: FastifyPluginOptions
) {
  // ✅ Catálogo
  const canRead = [requireAuth, requireRoles([1, 2, 3])]; // admin + staff
  const canWrite = [requireAuth, requireRoles([1,3])]; // solo admin

  app.get("/health", { preHandler: canRead }, async () => ({
    module: "estado_noticias",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  /**
   * GET /api/estado-noticias
   * 🔐 roles [1,2]
   */
  app.get("/", { preHandler: canRead }, async (_req, reply) => {
    const db = getDb();
    try {
      const [rows] = await db.query<any[]>(
        `
        SELECT id, nombre
        FROM estado_noticias
        ORDER BY id ASC
        `
      );

      reply.header("Cache-Control", "no-store");
      return reply.send({ ok: true, items: rows ?? [] });
    } catch (err: any) {
      return reply
        .code(500)
        .send({ ok: false, message: "Error al listar estados", error: err?.message });
    }
  });

  // GET /:id (read)
  app.get("/:id", { preHandler: canRead }, async (req, reply) => {
    const p = IdParam.safeParse(req.params);
    if (!p.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const { id } = p.data;
    const db = getDb();

    try {
      const [rows] = await db.query<any[]>(
        `
        SELECT id, nombre
        FROM estado_noticias
        WHERE id = ?
        LIMIT 1
        `,
        [id]
      );

      reply.header("Cache-Control", "no-store");

      if (!rows?.length) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, item: rows[0] });
    } catch (err: any) {
      return reply
        .code(500)
        .send({ ok: false, message: "Error al obtener estado", error: err?.message });
    }
  });

  // POST / (write)
  app.post("/", { preHandler: canWrite }, async (req, reply) => {
    const parsed = CreateSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply
        .code(400)
        .send({ ok: false, message: "Payload inválido", errors: parsed.error.flatten() });
    }

    const nombre = parsed.data.nombre.trim();
    const db = getDb();

    try {
      const [result]: any = await db.query(
        "INSERT INTO estado_noticias (nombre) VALUES (?)",
        [nombre]
      );

      reply.header("Cache-Control", "no-store");
      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        item: { id: result.insertId, nombre },
      });
    } catch (err: any) {
      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "El estado ya existe" });
      }
      return reply
        .code(500)
        .send({ ok: false, message: "Error al crear estado", error: err?.message });
    }
  });

  // PUT /:id (write)
  app.put("/:id", { preHandler: canWrite }, async (req, reply) => {
    const pid = IdParam.safeParse(req.params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const parsed = UpdateSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply
        .code(400)
        .send({ ok: false, message: "Payload inválido", errors: parsed.error.flatten() });
    }

    if (!parsed.data.nombre) {
      return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
    }

    const { id } = pid.data;
    const nombre = parsed.data.nombre.trim();
    const db = getDb();

    try {
      const [result]: any = await db.query(
        "UPDATE estado_noticias SET nombre = ? WHERE id = ? LIMIT 1",
        [nombre, id]
      );

      reply.header("Cache-Control", "no-store");

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, updated: { id, nombre } });
    } catch (err: any) {
      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "El estado ya existe" });
      }
      return reply
        .code(500)
        .send({ ok: false, message: "Error al actualizar estado", error: err?.message });
    }
  });

  // DELETE /:id (write)
  app.delete("/:id", { preHandler: canWrite }, async (req, reply) => {
    const pid = IdParam.safeParse(req.params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const { id } = pid.data;
    const db = getDb();

    try {
      const [result]: any = await db.query(
        "DELETE FROM estado_noticias WHERE id = ? LIMIT 1",
        [id]
      );

      reply.header("Cache-Control", "no-store");

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      if (err?.errno === 1451 || err?.code === "ER_ROW_IS_REFERENCED_2") {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: está en uso por noticias",
        });
      }
      return reply
        .code(500)
        .send({ ok: false, message: "Error al eliminar estado", error: err?.message });
    }
  });
}
