// src/routers/prevision_medica.ts
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: prevision_medica
 * Campos: id (PK), nombre (VARCHAR UNIQUE idealmente)
 */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres").max(100, "Máximo 100 caracteres"),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z
      .string()
      .trim()
      .min(3, "El nombre debe tener al menos 3 caracteres")
      .max(100, "Máximo 100 caracteres")
      .optional(),
  })
  .strict();

function normalize(row: any) {
  return {
    id: Number(row.id),
    nombre: String(row.nombre ?? ""),
  };
}

export default async function prevision_medica(app: FastifyInstance) {
  // ✅ Reglas (catálogo global)
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  // ───────────────────── Health (READ) ─────────────────────
  app.get("/health", { preHandler: canRead }, async () => ({
    module: "prevision_medica",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // ───────────────────── GET all (READ) ─────────────────────
  app.get("/", { preHandler: canRead }, async (_req: FastifyRequest, reply: FastifyReply) => {
    try {
      const [rows]: any = await db.query(
        "SELECT id, nombre FROM prevision_medica ORDER BY nombre ASC, id ASC"
      );

      return reply.send({
        ok: true,
        count: rows?.length ?? 0,
        items: (rows ?? []).map(normalize),
      });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al listar prevision_medica",
        error: err?.message,
      });
    }
  });

  // ───────────────────── GET by ID (READ) ─────────────────────
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: parsed.error.issues[0]?.message ?? "ID inválido" });
    }

    const id = parsed.data.id;

    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM prevision_medica WHERE id = ? LIMIT 1", [id]);

      if (!rows?.length) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al obtener prevision_medica",
        error: err?.message,
      });
    }
  });

  // ───────────────────── POST crear (WRITE) ─────────────────────
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const body = CreateSchema.parse(req.body);
      const nombre = body.nombre.trim();

      const [result]: any = await db.query("INSERT INTO prevision_medica (nombre) VALUES (?)", [nombre]);

      return reply.code(201).send({ ok: true, id: result.insertId, nombre });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
      }

      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "Ya existe una previsión con ese nombre" });
      }

      return reply.code(500).send({ ok: false, message: "Error al crear prevision_medica", error: err?.message });
    }
  });

  // ───────────────────── PUT actualizar (WRITE) ─────────────────────
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const p = IdParam.safeParse(req.params);
    if (!p.success) return reply.code(400).send({ ok: false, message: p.error.issues[0]?.message ?? "ID inválido" });
    const id = p.data.id;

    try {
      const body = UpdateSchema.parse(req.body);

      if (Object.keys(body).length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const changes: any = {};
      if (body.nombre !== undefined) changes.nombre = body.nombre.trim();

      const [result]: any = await db.query("UPDATE prevision_medica SET ? WHERE id = ?", [changes, id]);

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, updated: { id, ...changes } });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
      }

      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "Nombre duplicado" });
      }

      return reply.code(500).send({ ok: false, message: "Error al actualizar prevision_medica", error: err?.message });
    }
  });

  // ───────────────────── DELETE eliminar (WRITE) ─────────────────────
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const p = IdParam.safeParse(req.params);
    if (!p.success) return reply.code(400).send({ ok: false, message: p.error.issues[0]?.message ?? "ID inválido" });

    const id = p.data.id;

    try {
      const [result]: any = await db.query("DELETE FROM prevision_medica WHERE id = ?", [id]);

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: tiene registros asociados",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(500).send({ ok: false, message: "Error al eliminar", error: err?.message });
    }
  });
}
