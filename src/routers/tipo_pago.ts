// src/routers/tipo_pago.ts
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: tipo_pago
 * Campos: id (PK), nombre (VARCHAR UNIQUE idealmente)
 * Catálogo de tipos de pago
 */

const IdParam = z.object({ id: z.coerce.number().int().positive() });

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres").max(100, "Máximo 100 caracteres"),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres").max(100, "Máximo 100 caracteres").optional(),
  })
  .strict();

function normalize(row: any) {
  return {
    id: Number(row.id),
    nombre: String(row.nombre ?? ""),
  };
}

export default async function tipo_pago(app: FastifyInstance) {
  // ✅ Permisos reales (WELI):
  // - READ: 1,2,3
  // - WRITE: 1,3
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  // ───────────────────── Health (READ) ─────────────────────
  app.get("/health", { preHandler: canRead }, async (_req, reply) => {
    reply.header("Cache-Control", "no-store");
    return {
      module: "tipo_pago",
      status: "ready",
      timestamp: new Date().toISOString(),
    };
  });

  // ───────────────────── GET all (READ) ─────────────────────
  app.get("/", { preHandler: canRead }, async (_req: FastifyRequest, reply: FastifyReply) => {
    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM tipo_pago ORDER BY id ASC");
      reply.header("Cache-Control", "no-store");
      return reply.send({
        ok: true,
        count: rows?.length ?? 0,
        items: (rows ?? []).map(normalize),
      });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al listar tipo_pago", error: err?.message });
    }
  });

  // ───────────────────── GET by ID (READ) ─────────────────────
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsed.data.id;

    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM tipo_pago WHERE id = ? LIMIT 1", [id]);
      reply.header("Cache-Control", "no-store");

      if (!rows?.length) return reply.code(404).send({ ok: false, message: "Tipo de pago no encontrado" });

      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al obtener tipo_pago", error: err?.message });
    }
  });

  // ───────────────────── POST create (WRITE) ─────────────────────
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const parsed = CreateSchema.parse((req as any).body);
      const nombre = parsed.nombre.trim();

      const [result]: any = await db.query("INSERT INTO tipo_pago (nombre) VALUES (?)", [nombre]);

      return reply.code(201).send({ ok: true, id: result.insertId, nombre });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: "Datos inválidos", detail });
      }

      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "Ya existe un tipo de pago con ese nombre" });
      }

      return reply.code(500).send({ ok: false, message: "Error al crear tipo_pago", error: err?.message });
    }
  });

  // ───────────────────── PUT update (WRITE) ─────────────────────
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const p = IdParam.safeParse((req as any).params);
    if (!p.success) return reply.code(400).send({ ok: false, message: "ID inválido" });
    const id = p.data.id;

    try {
      const parsed = UpdateSchema.parse((req as any).body);

      if (Object.keys(parsed).length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const setClauses: string[] = [];
      const values: any[] = [];

      if (parsed.nombre !== undefined) {
        setClauses.push("nombre = ?");
        values.push(parsed.nombre.trim());
      }

      values.push(id);

      const [result]: any = await db.query(
        `UPDATE tipo_pago SET ${setClauses.join(", ")} WHERE id = ?`,
        values
      );

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "Tipo de pago no encontrado" });
      }

      return reply.send({ ok: true, updated: { id, ...parsed } });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: "Datos inválidos", detail });
      }

      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "Ya existe un tipo de pago con ese nombre" });
      }

      return reply.code(500).send({ ok: false, message: "Error al actualizar tipo_pago", error: err?.message });
    }
  });

  // ───────────────────── DELETE (WRITE) ─────────────────────
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const p = IdParam.safeParse((req as any).params);
    if (!p.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = p.data.id;

    try {
      const [result]: any = await db.query("DELETE FROM tipo_pago WHERE id = ?", [id]);

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "Tipo de pago no encontrado" });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      if (err?.errno === 1451) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: hay pagos vinculados a este tipo de pago.",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(500).send({ ok: false, message: "Error al eliminar tipo_pago", error: err?.message });
    }
  });
}
