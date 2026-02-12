// src/routers/establec_educ.ts
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: establec_educ
 * Campos: id (PK), nombre (VARCHAR UNIQUE)
 * Scope: catálogo global (sin academia)
 */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(3, "Debe tener al menos 3 caracteres").max(100),
  })
  .strict();

// PUT = reemplazo (nombre requerido)
const PutSchema = z
  .object({
    nombre: z.string().trim().min(3, "Debe tener al menos 3 caracteres").max(100),
  })
  .strict();

// PATCH = parcial
const PatchSchema = z
  .object({
    nombre: z.string().trim().min(3, "Debe tener al menos 3 caracteres").max(100).optional(),
  })
  .strict();

function normalize(row: any) {
  return {
    id: Number(row.id),
    nombre: String(row.nombre ?? ""),
  };
}

function zodDetail(err: ZodError) {
  return err.issues.map((i) => `${i.path.join(".") || "field"}: ${i.message}`).join("; ");
}

// (opcional pero recomendado) check de duplicado “suave”
async function existsByNombre(nombre: string, excludeId?: number) {
  const n = String(nombre ?? "").trim();
  if (!n) return false;

  if (excludeId) {
    const [rows]: any = await db.query(
      "SELECT id FROM establec_educ WHERE LOWER(TRIM(nombre)) = LOWER(?) AND id <> ? LIMIT 1",
      [n, excludeId]
    );
    return Array.isArray(rows) && rows.length > 0;
  }

  const [rows]: any = await db.query(
    "SELECT id FROM establec_educ WHERE LOWER(TRIM(nombre)) = LOWER(?) LIMIT 1",
    [n]
  );
  return Array.isArray(rows) && rows.length > 0;
}

export default async function establec_educ(app: FastifyInstance) {
  // ✅ Catálogo global:
  // - READ: roles 1/2/3
  // - WRITE: roles 1/3
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  // Health
  app.get("/health", { preHandler: canRead }, async (_req, reply) => {
    reply.header("Cache-Control", "no-store");
    return {
      module: "establec_educ",
      status: "ready",
      timestamp: new Date().toISOString(),
    };
  });

  // GET /
  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const [rows]: any = await db.query(
        "SELECT id, nombre FROM establec_educ ORDER BY nombre ASC, id ASC"
      );

      reply.header("Cache-Control", "no-store");
      return reply.send({
        ok: true,
        count: rows?.length ?? 0,
        items: (rows || []).map(normalize),
      });
    } catch (err: any) {
      req.log.error({ err }, "establec_educ: error listando establecimientos");
      return reply.code(500).send({
        ok: false,
        message: "Error al listar establecimientos",
        detail: err?.message,
      });
    }
  });

  // GET /:id
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsed.data.id;

    try {
      const [rows]: any = await db.query(
        "SELECT id, nombre FROM establec_educ WHERE id = ? LIMIT 1",
        [id]
      );

      reply.header("Cache-Control", "no-store");
      if (!rows?.length) return reply.code(404).send({ ok: false, message: "Establecimiento no encontrado" });

      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      req.log.error({ err, id }, "establec_educ: error obteniendo establecimiento por id");
      return reply.code(500).send({
        ok: false,
        message: "Error al obtener establecimiento",
        detail: err?.message,
      });
    }
  });

  // POST /
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const parsed = CreateSchema.parse(req.body);
      const nombre = parsed.nombre.trim();

      const dup = await existsByNombre(nombre);
      if (dup) return reply.code(409).send({ ok: false, message: "El establecimiento ya existe" });

      const [result]: any = await db.query("INSERT INTO establec_educ (nombre) VALUES (?)", [nombre]);

      reply.header("Cache-Control", "no-store");
      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        item: { id: result.insertId, nombre },
      });
    } catch (err: any) {
      if (err instanceof ZodError) {
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail: zodDetail(err) });
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "El establecimiento ya existe" });
      }

      req.log.error({ err }, "establec_educ: error creando establecimiento");
      return reply.code(500).send({
        ok: false,
        message: "Error al crear establecimiento",
        detail: err?.message,
      });
    }
  });

  // PUT /:id
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsedId = IdParam.safeParse(req.params);
    if (!parsedId.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsedId.data.id;

    try {
      const body = PutSchema.parse(req.body);
      const nombre = body.nombre.trim();

      const dup = await existsByNombre(nombre, id);
      if (dup) return reply.code(409).send({ ok: false, message: "El establecimiento ya existe" });

      const [result]: any = await db.query("UPDATE establec_educ SET nombre = ? WHERE id = ?", [nombre, id]);

      reply.header("Cache-Control", "no-store");
      if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, updated: { id, nombre } });
    } catch (err: any) {
      if (err instanceof ZodError) {
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail: zodDetail(err) });
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "El establecimiento ya existe" });
      }

      req.log.error({ err, id }, "establec_educ: error actualizando establecimiento");
      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar establecimiento",
        detail: err?.message,
      });
    }
  });

  // PATCH /:id
  app.patch("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsedId = IdParam.safeParse(req.params);
    if (!parsedId.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsedId.data.id;

    try {
      const body = PatchSchema.parse(req.body);
      if (Object.keys(body).length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      if (body.nombre !== undefined) {
        const nombre = body.nombre.trim();

        const dup = await existsByNombre(nombre, id);
        if (dup) return reply.code(409).send({ ok: false, message: "El establecimiento ya existe" });

        const [result]: any = await db.query("UPDATE establec_educ SET nombre = ? WHERE id = ?", [nombre, id]);

        reply.header("Cache-Control", "no-store");
        if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

        return reply.send({ ok: true, updated: { id, nombre } });
      }

      return reply.code(400).send({ ok: false, message: "No hay campos válidos para actualizar" });
    } catch (err: any) {
      if (err instanceof ZodError) {
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail: zodDetail(err) });
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "El establecimiento ya existe" });
      }

      req.log.error({ err, id }, "establec_educ: error patch establecimiento");
      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar establecimiento",
        detail: err?.message,
      });
    }
  });

  // DELETE /:id
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsed.data.id;

    try {
      const [result]: any = await db.query("DELETE FROM establec_educ WHERE id = ?", [id]);

      reply.header("Cache-Control", "no-store");
      if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      const isFk =
        err?.errno === 1451 ||
        err?.code === "ER_ROW_IS_REFERENCED_2" ||
        String(err?.code || "").includes("ER_ROW_IS_REFERENCED");

      if (isFk) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: hay jugadores asociados a este establecimiento",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      req.log.error({ err, id }, "establec_educ: error eliminando establecimiento");
      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar establecimiento",
        detail: err?.message,
      });
    }
  });
}
