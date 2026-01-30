// src/routers/tipo_pago.ts
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { db } from "../db";

// ✅ Ajusta si tu path difiere
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: tipo_pago
 * Campos: id (PK), nombre (VARCHAR UNIQUE idealmente)
 * Catálogo de tipos de pago
 */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres"),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres").optional(),
  })
  .strict();

const allowedKeys = new Set(["nombre"]);

function pickAllowed(body: Record<string, any>) {
  const out: Record<string, any> = {};
  for (const k in body) if (allowedKeys.has(k)) out[k] = body[k];
  return out;
}

function normalize(row: any) {
  return {
    id: Number(row.id),
    nombre: String(row.nombre ?? ""),
  };
}

export default async function tipo_pago(app: FastifyInstance) {
  // ✅ Regla de oro:
  // - READ: roles 1 y 2
  // - WRITE: solo rol 1
  const canRead = [requireAuth, requireRoles([1, 2])];
  const canWrite = [requireAuth, requireRoles([1])];

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
      return reply.code(500).send({
        ok: false,
        message: "Error al listar tipo_pago",
        error: err?.message,
      });
    }
  });

  // ───────────────────── GET by ID (READ) ─────────────────────
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    const id = parsed.data.id;

    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM tipo_pago WHERE id = ? LIMIT 1", [id]);

      reply.header("Cache-Control", "no-store");

      if (!rows?.length) {
        return reply.code(404).send({ ok: false, message: "Tipo de pago no encontrado" });
      }

      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al obtener tipo_pago",
        error: err?.message,
      });
    }
  });

  // ───────────────────── POST create (WRITE) ─────────────────────
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = CreateSchema.safeParse((req as any).body);
    if (!parsed.success) {
      const detail = parsed.error.issues.map((iss) => `${iss.path.join(".")}: ${iss.message}`).join("; ");
      return reply.code(400).send({ ok: false, message: "Datos inválidos", detail });
    }

    const data = pickAllowed(parsed.data);
    data.nombre = String(data.nombre ?? "").trim();

    try {
      const [result]: any = await db.query("INSERT INTO tipo_pago (nombre) VALUES (?)", [data.nombre]);

      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        ...data,
      });
    } catch (err: any) {
      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "Ya existe un tipo de pago con ese nombre" });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al crear tipo_pago",
        error: err?.message,
      });
    }
  });

  // ───────────────────── PUT update (WRITE) ─────────────────────
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const p = IdParam.safeParse((req as any).params);
    if (!p.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = p.data.id;

    const parsed = UpdateSchema.safeParse((req as any).body);
    if (!parsed.success) {
      const detail = parsed.error.issues.map((iss) => `${iss.path.join(".")}: ${iss.message}`).join("; ");
      return reply.code(400).send({ ok: false, message: "Datos inválidos", detail });
    }

    const changes = pickAllowed(parsed.data);

    if (changes.nombre !== undefined) changes.nombre = String(changes.nombre).trim();

    if (Object.keys(changes).length === 0) {
      return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
    }

    // compatibilidad máxima: UPDATE con SET explícito
    const setClauses: string[] = [];
    const values: any[] = [];

    if (changes.nombre !== undefined) {
      setClauses.push("nombre = ?");
      values.push(changes.nombre);
    }

    values.push(id);

    try {
      const [result]: any = await db.query(`UPDATE tipo_pago SET ${setClauses.join(", ")} WHERE id = ?`, values);

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "Tipo de pago no encontrado" });
      }

      return reply.send({ ok: true, updated: { id, ...changes } });
    } catch (err: any) {
      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "Ya existe un tipo de pago con ese nombre" });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar tipo_pago",
        error: err?.message,
      });
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

      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar tipo_pago",
        error: err?.message,
      });
    }
  });
}
