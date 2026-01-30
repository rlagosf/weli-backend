// src/routers/posiciones.ts
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";

// ✅ Ajusta si tu path difiere
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: posiciones
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

// Normalización de salida
function normalize(row: any) {
  return {
    id: Number(row.id),
    nombre: String(row.nombre ?? ""),
  };
}

export default async function posiciones(app: FastifyInstance) {
  // ✅ Regla de oro:
  // - READ: roles 1 y 2
  // - WRITE: solo rol 1
  const canRead = [requireAuth, requireRoles([1, 2])];
  const canWrite = [requireAuth, requireRoles([1])];

  // ───────────────────── Healthcheck (READ) ─────────────────────
  app.get(
    "/health",
    { preHandler: canRead },
    async () => ({
      module: "posiciones",
      status: "ready",
      timestamp: new Date().toISOString(),
    })
  );

  // ───────────────────── GET /posiciones (READ) ─────────────────────
  app.get(
    "/",
    { preHandler: canRead },
    async (_req: FastifyRequest, reply: FastifyReply) => {
      try {
        const [rows]: any = await db.query("SELECT id, nombre FROM posiciones ORDER BY id ASC");

        return reply.send({
          ok: true,
          count: rows.length,
          items: rows.map(normalize),
        });
      } catch (err: any) {
        return reply.code(500).send({
          ok: false,
          message: "Error al listar posiciones",
          error: err?.message,
        });
      }
    }
  );

  // ───────────────────── GET /posiciones/:id (READ) ─────────────────────
  app.get(
    "/:id",
    { preHandler: canRead },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse((req as any).params);
      if (!parsed.success) {
        return reply.code(400).send({ ok: false, message: "ID inválido" });
      }

      const id = parsed.data.id;

      try {
        const [rows]: any = await db.query(
          "SELECT id, nombre FROM posiciones WHERE id = ? LIMIT 1",
          [id]
        );

        if (!rows || rows.length === 0) {
          return reply.code(404).send({ ok: false, message: "Posición no encontrada" });
        }

        return reply.send({ ok: true, item: normalize(rows[0]) });
      } catch (err: any) {
        return reply.code(500).send({
          ok: false,
          message: "Error al obtener posición",
          error: err?.message,
        });
      }
    }
  );

  // ───────────────────── POST /posiciones (WRITE) ─────────────────────
  app.post(
    "/",
    { preHandler: canWrite },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const parsed = CreateSchema.parse((req as any).body);
        const nombre = parsed.nombre.trim();

        const [result]: any = await db.query(
          "INSERT INTO posiciones (nombre) VALUES (?)",
          [nombre]
        );

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
          return reply.code(409).send({ ok: false, message: "La posición ya existe" });
        }

        return reply.code(500).send({
          ok: false,
          message: "Error al crear posición",
          error: err?.message,
        });
      }
    }
  );

  // ───────────────────── PUT /posiciones/:id (WRITE) ─────────────────────
  app.put(
    "/:id",
    { preHandler: canWrite },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const pid = IdParam.safeParse((req as any).params);
      if (!pid.success) {
        return reply.code(400).send({ ok: false, message: "ID inválido" });
      }
      const id = pid.data.id;

      try {
        const parsed = UpdateSchema.parse((req as any).body);
        const changes = parsed;

        // ✅ robustez: si viene {}, no hacemos UPDATE
        if (Object.keys(changes).length === 0) {
          return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
        }

        const [result]: any = await db.query("UPDATE posiciones SET ? WHERE id = ?", [
          changes,
          id,
        ]);

        if (result.affectedRows === 0) {
          return reply.code(404).send({ ok: false, message: "No encontrado" });
        }

        return reply.send({ ok: true, updated: { id, ...changes } });
      } catch (err: any) {
        if (err instanceof ZodError) {
          const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
          return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
        }

        if (err?.errno === 1062) {
          return reply.code(409).send({ ok: false, message: "La posición ya existe" });
        }

        return reply.code(500).send({
          ok: false,
          message: "Error al actualizar posición",
          error: err?.message,
        });
      }
    }
  );

  // ───────────────────── DELETE /posiciones/:id (WRITE) ─────────────────────
  app.delete(
    "/:id",
    { preHandler: canWrite },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse((req as any).params);
      if (!parsed.success) {
        return reply.code(400).send({ ok: false, message: "ID inválido" });
      }

      const id = parsed.data.id;

      try {
        const [result]: any = await db.query("DELETE FROM posiciones WHERE id = ?", [id]);

        if (result.affectedRows === 0) {
          return reply.code(404).send({ ok: false, message: "No encontrado" });
        }

        return reply.send({ ok: true, deleted: id });
      } catch (err: any) {
        // FK constraint (jugadores.posicion_id)
        if (err?.errno === 1451) {
          return reply.code(409).send({
            ok: false,
            message: "No se puede eliminar: hay jugadores vinculados a esta posición.",
            detail: err?.sqlMessage ?? err?.message,
          });
        }

        return reply.code(500).send({
          ok: false,
          message: "Error al eliminar posición",
          error: err?.message,
        });
      }
    }
  );
}
