// src/routers/categorias.ts
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import {
  requireAuth,
  requireRoles,
  getEffectiveAcademiaId, // ✅ estándar único (opción 2)
} from "../middlewares/authz";

/**
 * Tabla: categorias
 * Campos: id (PK), academia_id (INT), nombre (VARCHAR)
 * UNIQUE recomendado: (academia_id, nombre)
 */

const IdParam = z.object({ id: z.coerce.number().int().positive() });

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(1, "nombre requerido").max(100),
  })
  .strict();

// ✅ PUT = reemplazo (nombre requerido)
const PutSchema = z
  .object({
    nombre: z.string().trim().min(1, "nombre requerido").max(100),
  })
  .strict();

// ✅ PATCH = parcial
const PatchSchema = z
  .object({
    nombre: z.string().trim().min(1, "nombre requerido").max(100).optional(),
  })
  .strict();

function normalize(row: any) {
  return {
    id: Number(row.id),
    academia_id: row.academia_id != null ? Number(row.academia_id) : null,
    nombre: String(row.nombre ?? ""),
  };
}

function zodDetail(err: ZodError) {
  return err.issues.map((i) => `${i.path.join(".") || "field"}: ${i.message}`).join("; ");
}

async function existsByNombreScoped(
  academiaId: number,
  nombre: string,
  excludeId?: number
) {
  const n = String(nombre ?? "").trim();
  if (!n) return false;

  if (excludeId) {
    const [rows]: any = await db.query(
      "SELECT id FROM categorias WHERE academia_id = ? AND LOWER(TRIM(nombre)) = LOWER(?) AND id <> ? LIMIT 1",
      [academiaId, n, excludeId]
    );
    return Array.isArray(rows) && rows.length > 0;
  }

  const [rows]: any = await db.query(
    "SELECT id FROM categorias WHERE academia_id = ? AND LOWER(TRIM(nombre)) = LOWER(?) LIMIT 1",
    [academiaId, n]
  );
  return Array.isArray(rows) && rows.length > 0;
}

export default async function categorias(app: FastifyInstance) {
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  app.get("/health", { preHandler: canRead }, async (_req, reply) => {
    reply.header("Cache-Control", "no-store");
    return { module: "categorias", status: "ready", timestamp: new Date().toISOString() };
  });

  // GET /
  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academiaId = getEffectiveAcademiaId(req);

      const [rows]: any = await db.query(
        "SELECT id, academia_id, nombre FROM categorias WHERE academia_id = ? ORDER BY nombre ASC, id ASC",
        [academiaId]
      );

      reply.header("Cache-Control", "no-store");
      return reply.send({ ok: true, count: rows?.length ?? 0, items: (rows || []).map(normalize) });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al consultar categorías", detail: err?.message });
    }
  });

  // GET /:id
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    try {
      const academiaId = getEffectiveAcademiaId(req);
      const id = parsed.data.id;

      const [rows]: any = await db.query(
        "SELECT id, academia_id, nombre FROM categorias WHERE id = ? AND academia_id = ? LIMIT 1",
        [id, academiaId]
      );

      reply.header("Cache-Control", "no-store");
      if (!rows?.length) return reply.code(404).send({ ok: false, message: "No encontrada" });
      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al buscar categoría", detail: err?.message });
    }
  });

  // POST /
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const body = CreateSchema.parse(req.body);
      const nombre = body.nombre.trim();
      const academiaId = getEffectiveAcademiaId(req);

      const dup = await existsByNombreScoped(academiaId, nombre);
      if (dup) return reply.code(409).send({ ok: false, message: "La categoría ya existe en esta academia" });

      const [result]: any = await db.query(
        "INSERT INTO categorias (academia_id, nombre) VALUES (?, ?)",
        [academiaId, nombre]
      );

      reply.header("Cache-Control", "no-store");
      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        item: { id: result.insertId, academia_id: academiaId, nombre },
      });
    } catch (err: any) {
      if (err instanceof ZodError) {
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail: zodDetail(err) });
      }
      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "La categoría ya existe en esta academia" });
      }
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al crear categoría", detail: err?.message });
    }
  });

  // PUT /:id (reemplazo)
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const idParsed = IdParam.safeParse(req.params);
    if (!idParsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    try {
      const academiaId = getEffectiveAcademiaId(req);
      const id = idParsed.data.id;

      const body = PutSchema.parse(req.body);
      const nombre = body.nombre.trim();

      const dup = await existsByNombreScoped(academiaId, nombre, id);
      if (dup) return reply.code(409).send({ ok: false, message: "La categoría ya existe en esta academia" });

      const [result]: any = await db.query(
        "UPDATE categorias SET nombre = ? WHERE id = ? AND academia_id = ?",
        [nombre, id, academiaId]
      );

      reply.header("Cache-Control", "no-store");
      if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrada" });

      return reply.send({ ok: true, updated: { id, nombre } });
    } catch (err: any) {
      if (err instanceof ZodError) {
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail: zodDetail(err) });
      }
      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "La categoría ya existe en esta academia" });
      }
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al actualizar categoría", detail: err?.message });
    }
  });

  // PATCH /:id (parcial)
  app.patch("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const idParsed = IdParam.safeParse(req.params);
    if (!idParsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    try {
      const academiaId = getEffectiveAcademiaId(req);
      const id = idParsed.data.id;

      const body = PatchSchema.parse(req.body);
      if (Object.keys(body).length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      if (body.nombre !== undefined) {
        const nombre = body.nombre.trim();

        const dup = await existsByNombreScoped(academiaId, nombre, id);
        if (dup) return reply.code(409).send({ ok: false, message: "La categoría ya existe en esta academia" });

        const [result]: any = await db.query(
          "UPDATE categorias SET nombre = ? WHERE id = ? AND academia_id = ?",
          [nombre, id, academiaId]
        );

        reply.header("Cache-Control", "no-store");
        if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrada" });

        return reply.send({ ok: true, updated: { id, nombre } });
      }

      return reply.code(400).send({ ok: false, message: "No hay campos válidos para actualizar" });
    } catch (err: any) {
      if (err instanceof ZodError) {
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail: zodDetail(err) });
      }
      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "La categoría ya existe en esta academia" });
      }
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al actualizar categoría", detail: err?.message });
    }
  });

  // DELETE /:id
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    try {
      const academiaId = getEffectiveAcademiaId(req);
      const id = parsed.data.id;

      const [result]: any = await db.query(
        "DELETE FROM categorias WHERE id = ? AND academia_id = ?",
        [id, academiaId]
      );

      reply.header("Cache-Control", "no-store");
      if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrada" });

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      if (err?.errno === 1451 || err?.code === "ER_ROW_IS_REFERENCED_2") {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: está siendo usada por jugadores u otras entidades",
          detail: err?.sqlMessage ?? err?.message,
        });
      }
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al eliminar categoría", detail: err?.message });
    }
  });
}
