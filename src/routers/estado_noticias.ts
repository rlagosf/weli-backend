// src/routers/estado_noticias.ts
import type { FastifyInstance, FastifyPluginOptions } from "fastify";
import { z } from "zod";
import { getDb } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

const IdParam = z.object({
  id: z.string().regex(/^\d+$/, "ID inválido"),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(1, "nombre requerido").max(100, "máx 100 caracteres"),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z.string().trim().min(1, "nombre requerido").max(100, "máx 100 caracteres").optional(),
  })
  .strict();

export default async function estado_noticias(app: FastifyInstance, _opts: FastifyPluginOptions) {
  // ✅ Regla de oro: catálogos
  const canRead = [requireAuth, requireRoles([1, 2])]; // admin + staff
  const canWrite = [requireAuth, requireRoles([1])];   // solo admin

  // Health (read: roles 1/2)
  app.get("/health", { preHandler: canRead }, async () => ({
    module: "estado_noticias",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  /**
   * GET /api/estado-noticias
   * Catálogo liviano: id + nombre
   * 🔐 roles [1,2]
   */
  app.get("/", { preHandler: canRead }, async (_req, reply) => {
    const db = getDb();
    const [rows] = await db.query<any[]>(
      `
      SELECT id, nombre
      FROM estado_noticias
      ORDER BY id ASC
      `
    );
    return reply.send({ ok: true, items: rows ?? [] });
  });

  // GET /:id (read: roles 1/2)
  app.get("/:id", { preHandler: canRead }, async (req, reply) => {
    const p = IdParam.safeParse((req as any).params);
    if (!p.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = Number(p.data.id);
    const db = getDb();

    const [rows] = await db.query<any[]>(
      `
      SELECT id, nombre
      FROM estado_noticias
      WHERE id = ?
      LIMIT 1
      `,
      [id]
    );

    if (!rows?.length) return reply.code(404).send({ ok: false, message: "No encontrado" });

    return reply.send({ ok: true, item: rows[0] });
  });

  // POST / (write: solo rol 1)
  app.post("/", { preHandler: canWrite }, async (req, reply) => {
    const parsed = CreateSchema.safeParse((req as any).body);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Payload inválido", errors: parsed.error.flatten() });
    }

    const nombre = parsed.data.nombre.trim();
    const db = getDb();

    try {
      const [result]: any = await db.query("INSERT INTO estado_noticias (nombre) VALUES (?)", [nombre]);

      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        item: { id: result.insertId, nombre },
      });
    } catch (err: any) {
      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "El estado ya existe" });
      }
      return reply.code(500).send({ ok: false, message: "Error al crear estado", error: err?.message });
    }
  });

  // PUT /:id (write: solo rol 1)
  app.put("/:id", { preHandler: canWrite }, async (req, reply) => {
    const pid = IdParam.safeParse((req as any).params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const parsed = UpdateSchema.safeParse((req as any).body);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Payload inválido", errors: parsed.error.flatten() });
    }

    if (!parsed.data.nombre) {
      return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
    }

    const id = Number(pid.data.id);
    const nombre = parsed.data.nombre.trim();
    const db = getDb();

    try {
      const [result]: any = await db.query("UPDATE estado_noticias SET nombre = ? WHERE id = ?", [nombre, id]);

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, updated: { id, nombre } });
    } catch (err: any) {
      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "El estado ya existe" });
      }
      return reply.code(500).send({ ok: false, message: "Error al actualizar estado", error: err?.message });
    }
  });

  // DELETE /:id (write: solo rol 1)
  app.delete("/:id", { preHandler: canWrite }, async (req, reply) => {
    const pid = IdParam.safeParse((req as any).params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = Number(pid.data.id);
    const db = getDb();

    try {
      const [result]: any = await db.query("DELETE FROM estado_noticias WHERE id = ?", [id]);

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      // Si tienes FK (por ejemplo noticias -> estado_noticias), acá suele caer 1451
      if (err?.errno === 1451) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: está en uso por noticias",
        });
      }
      return reply.code(500).send({ ok: false, message: "Error al eliminar estado", error: err?.message });
    }
  });
}
