// src/routers/estado.ts
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: estado
 * Campos: id (PK), nombre (VARCHAR UNIQUE)
 * Scope: catálogo global (sin academia)
 */

const IdParam = z.object({ id: z.coerce.number().int().positive() });

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(100),
  })
  .strict();

const PutSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(100),
  })
  .strict();

const PatchSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(100).optional(),
  })
  .strict();

function normalize(row: any) {
  return { id: Number(row.id), nombre: String(row.nombre ?? "") };
}

function zodDetail(err: ZodError) {
  return err.issues.map((i) => `${i.path.join(".") || "field"}: ${i.message}`).join("; ");
}

async function existsByNombre(nombre: string, excludeId?: number) {
  const n = String(nombre ?? "").trim();
  if (!n) return false;

  if (excludeId) {
    const [rows]: any = await db.query(
      "SELECT id FROM estado WHERE LOWER(TRIM(nombre)) = LOWER(?) AND id <> ? LIMIT 1",
      [n, excludeId]
    );
    return Array.isArray(rows) && rows.length > 0;
  }

  const [rows]: any = await db.query(
    "SELECT id FROM estado WHERE LOWER(TRIM(nombre)) = LOWER(?) LIMIT 1",
    [n]
  );
  return Array.isArray(rows) && rows.length > 0;
}

export default async function estado(app: FastifyInstance) {
  // ✅ Catálogo global
  // - Read: roles 1/2/3
  // - Write: roles 1/3
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  // Health
  app.get("/health", { preHandler: canRead }, async (_req, reply) => {
    reply.header("Cache-Control", "no-store");
    return { module: "estado", status: "ready", timestamp: new Date().toISOString() };
  });

  // GET /
  app.get("/", { preHandler: canRead }, async (_req: FastifyRequest, reply: FastifyReply) => {
    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM estado ORDER BY id ASC");
      reply.header("Cache-Control", "no-store");
      return reply.send({ ok: true, count: rows?.length ?? 0, items: (rows ?? []).map(normalize) });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");
      return reply.code(500).send({ ok: false, message: "Error al listar estados", detail: err?.message });
    }
  });

  // GET /:id
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    const id = parsed.data.id;

    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM estado WHERE id = ? LIMIT 1", [id]);
      reply.header("Cache-Control", "no-store");

      if (!rows?.length) return reply.code(404).send({ ok: false, message: "Estado no encontrado" });
      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");
      return reply.code(500).send({ ok: false, message: "Error al obtener estado", detail: err?.message });
    }
  });

  // POST /
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const body = CreateSchema.parse(req.body);
      const nombre = body.nombre.trim();

      const dup = await existsByNombre(nombre);
      if (dup) {
        reply.header("Cache-Control", "no-store");
        return reply.code(409).send({ ok: false, message: "El estado ya existe" });
      }

      const [result]: any = await db.query("INSERT INTO estado (nombre) VALUES (?)", [nombre]);

      reply.header("Cache-Control", "no-store");
      return reply.code(201).send({ ok: true, id: result.insertId, item: { id: result.insertId, nombre } });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      if (err instanceof ZodError) {
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail: zodDetail(err) });
      }
      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "El estado ya existe" });
      }
      return reply.code(500).send({ ok: false, message: "Error al crear estado", detail: err?.message });
    }
  });

  // PUT /:id (reemplazo)
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsedID = IdParam.safeParse(req.params);
    if (!parsedID.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    const id = parsedID.data.id;

    try {
      const body = PutSchema.parse(req.body);
      const nombre = body.nombre.trim();

      const dup = await existsByNombre(nombre, id);
      if (dup) {
        reply.header("Cache-Control", "no-store");
        return reply.code(409).send({ ok: false, message: "El estado ya existe" });
      }

      const [result]: any = await db.query("UPDATE estado SET nombre = ? WHERE id = ? LIMIT 1", [nombre, id]);

      reply.header("Cache-Control", "no-store");
      if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, updated: { id, nombre } });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      if (err instanceof ZodError) {
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail: zodDetail(err) });
      }
      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "El estado ya existe" });
      }
      return reply.code(500).send({ ok: false, message: "Error al actualizar estado", detail: err?.message });
    }
  });

  // PATCH /:id (parcial)
  app.patch("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsedID = IdParam.safeParse(req.params);
    if (!parsedID.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    const id = parsedID.data.id;

    try {
      const body = PatchSchema.parse(req.body);
      if (Object.keys(body).length === 0) {
        reply.header("Cache-Control", "no-store");
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      if (body.nombre !== undefined) {
        const nombre = body.nombre.trim();

        const dup = await existsByNombre(nombre, id);
        if (dup) {
          reply.header("Cache-Control", "no-store");
          return reply.code(409).send({ ok: false, message: "El estado ya existe" });
        }

        const [result]: any = await db.query("UPDATE estado SET nombre = ? WHERE id = ? LIMIT 1", [nombre, id]);

        reply.header("Cache-Control", "no-store");
        if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

        return reply.send({ ok: true, updated: { id, nombre } });
      }

      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "No hay campos válidos para actualizar" });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      if (err instanceof ZodError) {
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail: zodDetail(err) });
      }
      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "El estado ya existe" });
      }
      return reply.code(500).send({ ok: false, message: "Error al actualizar estado", detail: err?.message });
    }
  });

  // DELETE /:id
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    const id = parsed.data.id;

    try {
      const [result]: any = await db.query("DELETE FROM estado WHERE id = ? LIMIT 1", [id]);

      reply.header("Cache-Control", "no-store");
      if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: está en uso",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(500).send({ ok: false, message: "Error al eliminar estado", detail: err?.message });
    }
  });
}
