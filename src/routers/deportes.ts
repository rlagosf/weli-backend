import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: deportes
 * Campos: id (PK), nombre (VARCHAR UNIQUE)
 */

const IdParam = z.object({
  id: z.string().regex(/^\d+$/, "ID inválido"),
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
  // ✅ Regla de oro: catálogos
  const canRead = [requireAuth, requireRoles([3])]; // admin + staff
  const canWrite = [requireAuth, requireRoles([3])];   // solo admin

  // ───────────────────────────── Health (read: roles 1/2) ─────────────────────────────
  app.get("/health", { preHandler: canRead }, async () => ({
    module: "deportes",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // ───────────────────────────── GET all (read: roles 1/2) ─────────────────────────────
  app.get("/", { preHandler: canRead }, async (_req: FastifyRequest, reply: FastifyReply) => {
    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM deportes ORDER BY id ASC");

      return reply.send({
        ok: true,
        count: rows.length,
        items: rows.map(normalize),
      });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al listar deportes",
        error: err?.message,
      });
    }
  });

  // ───────────────────────────── GET by ID (read: roles 1/2) ─────────────────────────────
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = Number(parsed.data.id);

    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM deportes WHERE id = ? LIMIT 1", [id]);

      if (!rows.length) {
        return reply.code(404).send({
          ok: false,
          message: "Deporte no encontrado",
        });
      }

      return reply.send({
        ok: true,
        item: normalize(rows[0]),
      });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al obtener deporte",
        error: err?.message,
      });
    }
  });

  // ───────────────────────────── POST (write: solo rol 1) ─────────────────────────────
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
        const issues = err.issues.map((i) => `${i.path}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: issues });
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({
          ok: false,
          message: "El deporte ya existe",
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al crear deporte",
        error: err?.message,
      });
    }
  });

  // ───────────────────────────── PUT (write: solo rol 1) ─────────────────────────────
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsedID = IdParam.safeParse(req.params);
    if (!parsedID.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = Number(parsedID.data.id);

    try {
      const parsedBody = UpdateSchema.parse(req.body);

      if (!Object.keys(parsedBody).length) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const updates: any = { ...parsedBody };
      if (updates.nombre !== undefined) updates.nombre = String(updates.nombre).trim();

      const [result]: any = await db.query("UPDATE deportes SET ? WHERE id = ?", [updates, id]);

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrado" });
      }

      return reply.send({
        ok: true,
        updated: { id, ...updates },
      });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const issues = err.issues.map((i) => `${i.path}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: issues });
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({
          ok: false,
          message: "El deporte ya existe",
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar deporte",
        error: err?.message,
      });
    }
  });

  // ───────────────────────────── DELETE (write: solo rol 1) ─────────────────────────────
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = Number(parsed.data.id);

    try {
      const [result]: any = await db.query("DELETE FROM deportes WHERE id = ?", [id]);

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrado" });
      }

      return reply.send({
        ok: true,
        deleted: id,
      });
    } catch (err: any) {
      // FK en uso: 1451
      if (err?.errno === 1451 || err?.code === "ER_ROW_IS_REFERENCED_2") {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: está en uso",
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar deporte",
        error: err?.message,
      });
    }
  });
}
