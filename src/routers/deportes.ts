import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: deportes
 * Campos: id (PK), nombre (VARCHAR UNIQUE)
 * Scope: GLOBAL (solo superadmin rol 3)
 */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres"),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").optional(),
  })
  .strict();

function normalize(row: any) {
  return {
    id: Number(row.id),
    nombre: String(row.nombre ?? ""),
  };
}

export default async function deportes(app: FastifyInstance) {
  // ✅ Solo SUPERADMIN (rol 3)
  const canRead = [requireAuth, requireRoles([3])];
  const canWrite = [requireAuth, requireRoles([3])];

  // ───────── Health (rol 3) ─────────
  app.get("/health", { preHandler: canRead }, async () => ({
    module: "deportes",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // ───────── GET all (rol 3) ─────────
  app.get("/", { preHandler: canRead }, async (_req: FastifyRequest, reply: FastifyReply) => {
    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM deportes ORDER BY id ASC");
      return reply.send({
        ok: true,
        count: rows?.length ?? 0,
        items: (rows || []).map(normalize),
      });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al listar deportes",
        error: err?.message,
      });
    }
  });

  // ───────── GET by ID (rol 3) ─────────
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsed.data.id;

    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM deportes WHERE id = ? LIMIT 1", [id]);
      if (!rows?.length) return reply.code(404).send({ ok: false, message: "Deporte no encontrado" });

      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al obtener deporte",
        error: err?.message,
      });
    }
  });

  // ───────── POST (rol 3) ─────────
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const parsed = CreateSchema.parse(req.body);
      const nombre = parsed.nombre.trim();

      const [result]: any = await db.query("INSERT INTO deportes (nombre) VALUES (?)", [nombre]);

      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        nombre,
      });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const issues = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: issues });
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "El deporte ya existe" });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al crear deporte",
        error: err?.message,
      });
    }
  });

  // ───────── PUT (rol 3) ─────────
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsedID = IdParam.safeParse(req.params);
    if (!parsedID.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsedID.data.id;

    try {
      const parsedBody = UpdateSchema.parse(req.body);

      if (!Object.keys(parsedBody).length) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const nombre = parsedBody.nombre?.trim();
      if (nombre === undefined) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const [result]: any = await db.query("UPDATE deportes SET nombre = ? WHERE id = ? LIMIT 1", [nombre, id]);

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, updated: { id, nombre } });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const issues = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: issues });
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "El deporte ya existe" });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar deporte",
        error: err?.message,
      });
    }
  });

  // ───────── DELETE (rol 3) ─────────
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsed.data.id;

    try {
      const [result]: any = await db.query("DELETE FROM deportes WHERE id = ? LIMIT 1", [id]);

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      if (err?.errno === 1451 || err?.code === "ER_ROW_IS_REFERENCED_2") {
        return reply.code(409).send({ ok: false, message: "No se puede eliminar: está en uso" });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar deporte",
        error: err?.message,
      });
    }
  });
}
