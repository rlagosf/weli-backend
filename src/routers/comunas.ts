// src/routers/comunas.ts
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/* ───────── Schemas ───────── */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(1, "El nombre es obligatorio").max(100),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z.string().trim().min(1).max(100).optional(),
  })
  .strict();

/* ───────── Helpers ───────── */

function normalizeOut(row: any) {
  if (!row) return null;
  return {
    id: Number(row.id),
    nombre: String(row.nombre ?? ""),
  };
}

async function existsByNombre(nombre: string, excludeId?: number) {
  const n = nombre.trim();
  if (!n) return false;

  if (excludeId) {
    const [rows]: any = await db.query(
      "SELECT id FROM comunas WHERE LOWER(nombre) = LOWER(?) AND id <> ? LIMIT 1",
      [n, excludeId]
    );
    return Array.isArray(rows) && rows.length > 0;
  }

  const [rows]: any = await db.query(
    "SELECT id FROM comunas WHERE LOWER(nombre) = LOWER(?) LIMIT 1",
    [n]
  );
  return Array.isArray(rows) && rows.length > 0;
}

/* ───────── Router ───────── */

export default async function comunas(app: FastifyInstance) {
  // ✅ Catálogo global
  // - Read: roles 1/2/3
  // - Write: roles 1/3 (admin + superadmin)
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  // Health
  app.get("/health", { preHandler: canRead }, async () => ({
    module: "comunas",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // GET /comunas
  app.get("/", { preHandler: canRead }, async (_req: FastifyRequest, reply: FastifyReply) => {
    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM comunas ORDER BY nombre ASC");

      return reply.send({
        ok: true,
        items: (rows || []).map(normalizeOut),
        count: rows?.length ?? 0,
      });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al listar comunas",
        detail: err?.message,
      });
    }
  });

  // GET /comunas/:id
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pid = IdParam.safeParse(req.params);
    if (!pid.success) {
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    const { id } = pid.data;

    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM comunas WHERE id = ? LIMIT 1", [
        id,
      ]);

      if (!rows || rows.length === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrado" });
      }

      return reply.send({ ok: true, item: normalizeOut(rows[0]) });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al obtener comuna",
        detail: err?.message,
      });
    }
  });

  // POST /comunas
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const parsed = CreateSchema.parse(req.body);
      const nombre = parsed.nombre.trim();

      const dup = await existsByNombre(nombre);
      if (dup) {
        return reply.code(409).send({
          ok: false,
          field: "nombre",
          message: "Duplicado: la comuna ya existe",
        });
      }

      const [result]: any = await db.query("INSERT INTO comunas (nombre) VALUES (?)", [nombre]);

      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        item: { id: result.insertId, nombre },
      });
    } catch (err: any) {
      if (err instanceof ZodError) {
        return reply.code(400).send({
          ok: false,
          message: "Payload inválido",
          detail: err.issues.map((i) => i.message).join("; "),
        });
      }

      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "Duplicado: la comuna ya existe" });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al crear comuna",
        detail: err?.message,
      });
    }
  });

  // PATCH /comunas/:id
  app.patch("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pid = IdParam.safeParse(req.params);
    if (!pid.success) {
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    const { id } = pid.data;

    try {
      const parsed = UpdateSchema.parse(req.body);
      if (!parsed.nombre) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const nombre = parsed.nombre.trim();

      const dup = await existsByNombre(nombre, id);
      if (dup) {
        return reply.code(409).send({
          ok: false,
          field: "nombre",
          message: "Duplicado: la comuna ya existe",
        });
      }

      const [result]: any = await db.query("UPDATE comunas SET nombre = ? WHERE id = ?", [
        nombre,
        id,
      ]);

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrado" });
      }

      return reply.send({ ok: true, updated: { id, nombre } });
    } catch (err: any) {
      if (err instanceof ZodError) {
        return reply.code(400).send({
          ok: false,
          message: "Payload inválido",
          detail: err.issues.map((i) => i.message).join("; "),
        });
      }

      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "Duplicado: la comuna ya existe" });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar comuna",
        detail: err?.message,
      });
    }
  });

  // DELETE /comunas/:id
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pid = IdParam.safeParse(req.params);
    if (!pid.success) {
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    const { id } = pid.data;

    try {
      const [result]: any = await db.query("DELETE FROM comunas WHERE id = ?", [id]);

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrado" });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      if (err?.errno === 1451) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: hay jugadores asociados a esta comuna",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar comuna",
        detail: err?.message,
      });
    }
  });
}
