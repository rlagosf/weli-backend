// src/routers/categorias.ts
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: categorias
 * Campos esperados: id (PK), academia_id (INT), nombre (VARCHAR)
 * UNIQUE recomendado: (academia_id, nombre)
 */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(1, "nombre requerido").max(100),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z.string().trim().min(1, "nombre requerido").max(100),
  })
  .strict();

function normalize(row: any) {
  return {
    id: Number(row.id),
    academia_id: row.academia_id != null ? Number(row.academia_id) : null,
    nombre: String(row.nombre ?? ""),
  };
}

/* ──────────────────────────────────────────────────────────────
   Multi-academia helpers (WELI)
   Regla:
   - rol 1/2: academia_id desde token (req.user.academia_id)
   - rol 3: academia_id desde header x-academia-id (obligatorio)
────────────────────────────────────────────────────────────── */
function getUserRolId(req: FastifyRequest): number {
  const u: any = (req as any).user || {};
  const r = Number(u?.rol_id ?? u?.role_id ?? u?.role ?? 0);
  return Number.isFinite(r) ? r : 0;
}

function getEffectiveAcademiaId(req: FastifyRequest): number {
  const rol = getUserRolId(req);
  const u: any = (req as any).user || {};

  if (rol === 3) {
    const hdr = req.headers["x-academia-id"];
    const raw = Array.isArray(hdr) ? hdr[0] : hdr;
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0) {
      throw Object.assign(new Error("FORBIDDEN: falta x-academia-id para superadmin"), {
        statusCode: 403,
      });
    }
    return n;
  }

  const raw =
    u?.academia_id ??
    u?.academy_id ??
    u?.academiaId ??
    u?.academyId ??
    u?.academia ??
    u?.academy;

  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    throw Object.assign(new Error("FORBIDDEN: token sin academia_id"), { statusCode: 403 });
  }
  return n;
}

export default async function categorias(app: FastifyInstance) {
  // ✅ Regla de oro: catálogos
  // - Read: admin(1) + staff(2) + superadmin(3)
  // - Write: admin(1) + superadmin(3)
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  // Health (read)
  app.get("/health", { preHandler: canRead }, async () => ({
    module: "categorias",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // ───────────────────── GET /categorias (READ scoped) ─────────────────────
  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academiaId = getEffectiveAcademiaId(req);

      const [rows]: any = await db.query(
        "SELECT id, academia_id, nombre FROM categorias WHERE academia_id = ? ORDER BY nombre ASC, id ASC",
        [academiaId]
      );

      return reply.send({
        ok: true,
        count: rows?.length ?? 0,
        items: (rows || []).map(normalize),
      });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({
        ok: false,
        message: "Error al consultar categorías",
        detail: err?.message,
      });
    }
  });

  // ───────────────────── GET /categorias/:id (READ scoped) ─────────────────────
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

      if (!rows?.length) return reply.code(404).send({ ok: false, message: "No encontrada" });
      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({
        ok: false,
        message: "Error al buscar categoría",
        detail: err?.message,
      });
    }
  });

  // ───────────────────── POST /categorias (WRITE scoped) ─────────────────────
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const body = CreateSchema.parse(req.body);
      const nombre = body.nombre.trim();
      const academiaId = getEffectiveAcademiaId(req);

      const [result]: any = await db.query(
        "INSERT INTO categorias (academia_id, nombre) VALUES (?, ?)",
        [academiaId, nombre]
      );

      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        item: { id: result.insertId, academia_id: academiaId, nombre },
      });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "La categoría ya existe en esta academia" });
      }

      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al crear categoría", detail: err?.message });
    }
  });

  // ───────────────────── PUT /categorias/:id (WRITE scoped) ─────────────────────
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const idParsed = IdParam.safeParse(req.params);
    if (!idParsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    try {
      const academiaId = getEffectiveAcademiaId(req);
      const id = idParsed.data.id;

      const body = UpdateSchema.parse(req.body);
      const nombre = body.nombre.trim();
      if (!nombre) return reply.code(400).send({ ok: false, field: "nombre", message: "Nombre no puede ser vacío" });

      // ✅ update scoped: si no pertenece, affectedRows=0 -> 404
      const [result]: any = await db.query(
        "UPDATE categorias SET nombre = ? WHERE id = ? AND academia_id = ?",
        [nombre, id, academiaId]
      );

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrada" });
      }

      return reply.send({ ok: true, updated: { id, nombre } });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "La categoría ya existe en esta academia" });
      }

      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al actualizar categoría", detail: err?.message });
    }
  });

  // ───────────────────── DELETE /categorias/:id (WRITE scoped) ─────────────────────
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

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrada" });
      }

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
