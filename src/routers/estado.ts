// src/routers/estado.ts
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: estado
 * Campos: id (PK), nombre (VARCHAR UNIQUE)
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

export default async function estado(app: FastifyInstance) {
  // ✅ Catálogo (sin academia scope)
  const canRead = [requireAuth, requireRoles([1, 2, 3])]; // admin + staff + superadmin
  const canWrite = [requireAuth, requireRoles([1, 3])];  // admin + superadmin

  app.get("/health", { preHandler: canRead }, async () => ({
    module: "estado",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  app.get("/", { preHandler: canRead }, async (_req: FastifyRequest, reply: FastifyReply) => {
    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM estado ORDER BY id ASC");
      reply.header("Cache-Control", "no-store");
      return reply.send({
        ok: true,
        count: rows?.length ?? 0,
        items: (rows ?? []).map(normalize),
      });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al listar estados",
        error: err?.message,
      });
    }
  });

  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const { id } = parsed.data;

    try {
      const [rows]: any = await db.query(
        "SELECT id, nombre FROM estado WHERE id = ? LIMIT 1",
        [id]
      );

      reply.header("Cache-Control", "no-store");

      if (!rows?.length) {
        return reply.code(404).send({ ok: false, message: "Estado no encontrado" });
      }

      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al obtener estado",
        error: err?.message,
      });
    }
  });

  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const parsed = CreateSchema.parse(req.body);
      const nombre = parsed.nombre.trim();

      const [result]: any = await db.query(
        "INSERT INTO estado (nombre) VALUES (?)",
        [nombre]
      );

      reply.header("Cache-Control", "no-store");

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
        return reply.code(409).send({ ok: false, message: "El estado ya existe" });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al crear estado",
        error: err?.message,
      });
    }
  });

  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsedID = IdParam.safeParse(req.params);
    if (!parsedID.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const { id } = parsedID.data;

    try {
      const parsedBody = UpdateSchema.parse(req.body);

      if (!Object.keys(parsedBody).length) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const sets: string[] = [];
      const params: any[] = [];

      if (parsedBody.nombre !== undefined) {
        sets.push("nombre = ?");
        params.push(parsedBody.nombre.trim());
      }

      if (!sets.length) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      params.push(id);

      const [result]: any = await db.query(
        `UPDATE estado SET ${sets.join(", ")} WHERE id = ? LIMIT 1`,
        params
      );

      reply.header("Cache-Control", "no-store");

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrado" });
      }

      return reply.send({ ok: true, updated: { id, ...parsedBody } });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const issues = err.issues.map((i) => `${i.path}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: issues });
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "El estado ya existe" });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar estado",
        error: err?.message,
      });
    }
  });

  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const { id } = parsed.data;

    try {
      const [result]: any = await db.query(
        "DELETE FROM estado WHERE id = ? LIMIT 1",
        [id]
      );

      reply.header("Cache-Control", "no-store");

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrado" });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      if (err?.errno === 1451 || err?.code === "ER_ROW_IS_REFERENCED_2") {
        return reply.code(409).send({ ok: false, message: "No se puede eliminar: está en uso" });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar estado",
        error: err?.message,
      });
    }
  });
}
