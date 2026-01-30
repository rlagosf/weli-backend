import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";

// ✅ Ajusta si tu path difiere
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: roles
 * Campos: id (PK), nombre (VARCHAR UNIQUE)
 */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener mínimo 2 caracteres"),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener mínimo 2 caracteres").optional(),
  })
  .strict();

function normalize(row: any) {
  return {
    id: Number(row.id),
    nombre: String(row.nombre ?? ""),
  };
}

export default async function roles(app: FastifyInstance) {
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
      module: "roles",
      status: "ready",
      timestamp: new Date().toISOString(),
    })
  );

  // ───────────────────── GET /roles (READ) ─────────────────────
  app.get(
    "/",
    { preHandler: canRead },
    async (_req: FastifyRequest, reply: FastifyReply) => {
      try {
        const [rows]: any = await db.query("SELECT id, nombre FROM roles ORDER BY id ASC");

        return reply.send({
          ok: true,
          count: rows?.length ?? 0,
          items: (rows ?? []).map(normalize),
        });
      } catch (err: any) {
        return reply.code(500).send({
          ok: false,
          message: "Error al listar roles",
          error: err?.message,
        });
      }
    }
  );

  // ───────────────────── GET /roles/:id (READ) ─────────────────────
  app.get(
    "/:id",
    { preHandler: canRead },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse(req.params);
      if (!parsed.success) {
        return reply.code(400).send({ ok: false, message: "ID inválido" });
      }

      const id = parsed.data.id;

      try {
        const [rows]: any = await db.query("SELECT id, nombre FROM roles WHERE id = ? LIMIT 1", [id]);

        if (!rows?.length) {
          return reply.code(404).send({
            ok: false,
            message: "Rol no encontrado",
          });
        }

        return reply.send({ ok: true, item: normalize(rows[0]) });
      } catch (err: any) {
        return reply.code(500).send({
          ok: false,
          message: "Error al obtener rol",
          error: err?.message,
        });
      }
    }
  );

  // ───────────────────── POST /roles (WRITE) ─────────────────────
  app.post(
    "/",
    { preHandler: canWrite },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const parsed = CreateSchema.parse(req.body);
        const nombre = parsed.nombre.trim();

        const [result]: any = await db.query("INSERT INTO roles (nombre) VALUES (?)", [nombre]);

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
          return reply.code(409).send({ ok: false, message: "El rol ya existe" });
        }

        return reply.code(500).send({
          ok: false,
          message: "Error al crear rol",
          error: err?.message,
        });
      }
    }
  );

  // ───────────────────── PUT /roles/:id (WRITE) ─────────────────────
  app.put(
    "/:id",
    { preHandler: canWrite },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsedId = IdParam.safeParse(req.params);
      if (!parsedId.success) {
        return reply.code(400).send({ ok: false, message: "ID inválido" });
      }
      const id = parsedId.data.id;

      try {
        const parsed = UpdateSchema.parse(req.body);
        const changes = parsed;

        if (Object.keys(changes).length === 0) {
          return reply.code(400).send({
            ok: false,
            message: "No hay campos para actualizar",
          });
        }

        const [result]: any = await db.query("UPDATE roles SET ? WHERE id = ?", [changes, id]);

        if (result.affectedRows === 0) {
          return reply.code(404).send({ ok: false, message: "Rol no encontrado" });
        }

        return reply.send({
          ok: true,
          updated: { id, ...changes },
        });
      } catch (err: any) {
        if (err instanceof ZodError) {
          const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
          return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
        }

        if (err?.errno === 1062) {
          return reply.code(409).send({ ok: false, message: "El rol ya existe" });
        }

        return reply.code(500).send({
          ok: false,
          message: "Error al actualizar rol",
          error: err?.message,
        });
      }
    }
  );

  // ───────────────────── DELETE /roles/:id (WRITE) ─────────────────────
  app.delete(
    "/:id",
    { preHandler: canWrite },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse(req.params);
      if (!parsed.success) {
        return reply.code(400).send({ ok: false, message: "ID inválido" });
      }

      const id = parsed.data.id;

      try {
        const [result]: any = await db.query("DELETE FROM roles WHERE id = ?", [id]);

        if (result.affectedRows === 0) {
          return reply.code(404).send({
            ok: false,
            message: "Rol no encontrado",
          });
        }

        return reply.send({
          ok: true,
          deleted: id,
        });
      } catch (err: any) {
        if (err?.errno === 1451) {
          return reply.code(409).send({
            ok: false,
            message: "No se puede eliminar: hay usuarios vinculados a este rol.",
          });
        }

        return reply.code(500).send({
          ok: false,
         message: "Error al eliminar rol",
          error: err?.message,
        });
      }
    }
  );
}
