// src/routers/medio_pago.ts
import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: medio_pago
 * Campos: id (PK), nombre (VARCHAR UNIQUE)
 */

const IdParam = z.object({
  id: z.string().regex(/^\d+$/, "ID inválido"),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(100, "Máximo 100 caracteres"),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(100, "Máximo 100 caracteres").optional(),
  })
  .strict();

function normalize(row: any) {
  return {
    id: Number(row.id),
    nombre: String(row.nombre ?? ""),
  };
}

export default async function medio_pago(app: FastifyInstance) {
  // ✅ Regla de oro (catálogos)
  const canRead = [requireAuth, requireRoles([1, 2])]; // admin + staff
  const canWrite = [requireAuth, requireRoles([1])];  // solo admin

  // ───────────────────── Health (READ: 1/2) ─────────────────────
  app.get("/health", { preHandler: canRead }, async () => ({
    module: "medio_pago",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // ───────────────────── GET todos (READ: 1/2) ─────────────────────
  app.get("/", { preHandler: canRead }, async (_req: FastifyRequest, reply: FastifyReply) => {
    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM medio_pago ORDER BY id ASC");

      return reply.send({
        ok: true,
        count: rows?.length ?? 0,
        items: (rows || []).map(normalize),
      });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al listar medio_pago",
        error: err?.message,
      });
    }
  });

  // ───────────────────── GET por ID (READ: 1/2) ─────────────────────
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: parsed.error.issues[0]?.message ?? "ID inválido" });
    }

    const id = Number(parsed.data.id);

    try {
      const [rows]: any = await db.query(
        "SELECT id, nombre FROM medio_pago WHERE id = ? LIMIT 1",
        [id]
      );

      if (!rows?.length) {
        return reply.code(404).send({
          ok: false,
          message: "Medio de pago no encontrado",
        });
      }

      return reply.send({
        ok: true,
        item: normalize(rows[0]),
      });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al obtener medio_pago",
        error: err?.message,
      });
    }
  });

  // ───────────────────── POST (WRITE: solo 1) ─────────────────────
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const parsed = CreateSchema.parse(req.body);
      const nombre = parsed.nombre.trim();

      const [result]: any = await db.query("INSERT INTO medio_pago (nombre) VALUES (?)", [nombre]);

      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        nombre,
      });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
      }

      if (err?.errno === 1062) {
        return reply.code(409).send({
          ok: false,
          message: "El medio de pago ya existe",
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al crear medio_pago",
        error: err?.message,
      });
    }
  });

  // ───────────────────── PUT (WRITE: solo 1) ─────────────────────
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pid = IdParam.safeParse(req.params);
    if (!pid.success) {
      return reply.code(400).send({ ok: false, message: pid.error.issues[0]?.message ?? "ID inválido" });
    }

    const id = Number(pid.data.id);

    try {
      const parsed = UpdateSchema.parse(req.body);
      const changes = parsed;

      if (Object.keys(changes).length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const setClauses: string[] = [];
      const values: any[] = [];

      if (changes.nombre !== undefined) {
        setClauses.push("nombre = ?");
        values.push(changes.nombre.trim());
      }

      if (setClauses.length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      values.push(id);

      const [result]: any = await db.query(
        `UPDATE medio_pago SET ${setClauses.join(", ")} WHERE id = ?`,
        values
      );

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrado" });
      }

      return reply.send({
        ok: true,
        updated: { id, ...changes, nombre: changes.nombre?.trim?.() ?? changes.nombre },
      });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
      }

      if (err?.errno === 1062) {
        return reply.code(409).send({
          ok: false,
          message: "El medio de pago ya existe",
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar medio_pago",
        error: err?.message,
      });
    }
  });

  // ───────────────────── DELETE (WRITE: solo 1) ─────────────────────
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: parsed.error.issues[0]?.message ?? "ID inválido" });
    }

    const id = Number(parsed.data.id);

    try {
      const [result]: any = await db.query("DELETE FROM medio_pago WHERE id = ?", [id]);

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrado" });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: el medio de pago está siendo usado",
          error: err?.sqlMessage || err?.message,
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar medio_pago",
        error: err?.message,
      });
    }
  });
}
