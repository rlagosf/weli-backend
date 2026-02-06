// src/routers/situacion_pago.ts
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: situacion_pago
 * Campos: id (PK), nombre (VARCHAR UNIQUE)
 * Uso: catálogo de estado del pago (al día, moroso, becado, etc.)
 */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    nombre: z
      .string()
      .trim()
      .min(2, "Debe tener al menos 2 caracteres")
      .max(100, "Máximo 100 caracteres"),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z
      .string()
      .trim()
      .min(2, "Debe tener al menos 2 caracteres")
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

export default async function situacion_pago(app: FastifyInstance) {
  // ✅ Arquitectura WELI:
  // - READ: roles 1/2/3
  // - WRITE: solo rol 3 (superadmin)
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([3])];

  // ───────────────────── Healthcheck (READ) ─────────────────────
  app.get("/health", { preHandler: canRead }, async () => ({
    module: "situacion_pago",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // ───────────────────── GET /situacion_pago (READ) ─────────────────────
  app.get("/", { preHandler: canRead }, async (_req: FastifyRequest, reply: FastifyReply) => {
    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM situacion_pago ORDER BY id ASC");

      return reply.send({
        ok: true,
        count: rows?.length ?? 0,
        items: (rows ?? []).map(normalize),
      });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al listar situacion_pago",
        error: err?.message,
      });
    }
  });

  // ───────────────────── GET /situacion_pago/:id (READ) ─────────────────────
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: parsed.error.issues[0]?.message ?? "ID inválido" });
    }

    const id = parsed.data.id;

    try {
      const [rows]: any = await db.query(
        "SELECT id, nombre FROM situacion_pago WHERE id = ? LIMIT 1",
        [id]
      );

      if (!rows?.length) {
        return reply.code(404).send({ ok: false, message: "Situación de pago no encontrada" });
      }

      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al obtener situacion_pago",
        error: err?.message,
      });
    }
  });

  // ───────────────────── POST /situacion_pago (WRITE: solo 3) ─────────────────────
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = CreateSchema.safeParse(req.body);
    if (!parsed.success) {
      const detail = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
      return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
    }

    const nombre = parsed.data.nombre.trim();

    try {
      const [result]: any = await db.query("INSERT INTO situacion_pago (nombre) VALUES (?)", [nombre]);

      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        nombre,
      });
    } catch (err: any) {
      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "La situación de pago ya existe" });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al crear situacion_pago",
        error: err?.message,
      });
    }
  });

  // ───────────────────── PUT /situacion_pago/:id (WRITE: solo 3) ─────────────────────
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pid = IdParam.safeParse(req.params);
    if (!pid.success) {
      return reply.code(400).send({ ok: false, message: pid.error.issues[0]?.message ?? "ID inválido" });
    }
    const id = pid.data.id;

    const parsed = UpdateSchema.safeParse(req.body);
    if (!parsed.success) {
      const detail = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
      return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
    }

    const changes = parsed.data;
    if (Object.keys(changes).length === 0) {
      return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
    }

    // payload limpio (evita enviar undefined)
    const payload: any = {};
    if (changes.nombre !== undefined) payload.nombre = changes.nombre.trim();

    try {
      const [result]: any = await db.query("UPDATE situacion_pago SET ? WHERE id = ?", [payload, id]);

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "Situación de pago no encontrada" });
      }

      return reply.send({ ok: true, updated: { id, ...payload } });
    } catch (err: any) {
      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "La situación de pago ya existe" });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar situacion_pago",
        error: err?.message,
      });
    }
  });

  // ───────────────────── DELETE /situacion_pago/:id (WRITE: solo 3) ─────────────────────
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: parsed.error.issues[0]?.message ?? "ID inválido" });
    }

    const id = parsed.data.id;

    try {
      const [result]: any = await db.query("DELETE FROM situacion_pago WHERE id = ?", [id]);

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "Situación de pago no encontrada" });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: hay pagos de jugadores vinculados a esta situación de pago.",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar situacion_pago",
        error: err?.message,
      });
    }
  });
}
