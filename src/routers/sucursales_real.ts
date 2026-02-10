// src/routers/sucursalesReal.ts
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: sucursales_real
 * Campos: id (PK), academia_id (FK), nombre (VARCHAR)
 * Recomendado: UNIQUE(academia_id, nombre)
 */

const IdParam = z.object({ id: z.coerce.number().int().positive() });

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres").max(100, "Máximo 100 caracteres"),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z
      .string()
      .trim()
      .min(3, "El nombre debe tener al menos 3 caracteres")
      .max(100, "Máximo 100 caracteres")
      .optional(),
  })
  .strict();

const PageQuery = z.object({
  limit: z.coerce.number().int().positive().max(500).default(200),
  offset: z.coerce.number().int().nonnegative().default(0),
  q: z.string().trim().min(1).optional(),
});

function normalize(row: any) {
  return {
    id: Number(row.id),
    academia_id: row.academia_id != null ? Number(row.academia_id) : null,
    nombre: String(row.nombre ?? ""),
  };
}

/* ──────────────────────────────────────────────────────────────
   Multi-academia helpers (WELI) — MISMA REGLA QUE POSICIONES
   Regla:
   - rol 1/2: academia_id desde token
   - rol 3: academia_id desde header x-academia-id (obligatorio)
────────────────────────────────────────────────────────────── */
function getRolId(req: FastifyRequest): number {
  const a: any = (req as any).auth;
  const u: any = (req as any).user;
  const raw = a?.rol_id ?? u?.rol_id ?? u?.role_id ?? u?.role ?? 0;
  const n = Number(raw);
  return Number.isFinite(n) ? n : 0;
}

function getEffectiveAcademiaId(req: FastifyRequest): number {
  const rol = getRolId(req);

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

  const a: any = (req as any).auth;
  const u: any = (req as any).user;
  const raw =
    a?.academia_id ??
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

// escape mínimo para LIKE
function escapeLike(s: string) {
  return s.replace(/[\\%_]/g, (m) => `\\${m}`);
}

export default async function sucursales_real(app: FastifyInstance) {
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  app.get("/health", { preHandler: canRead }, async (_req, reply) => {
    reply.header("Cache-Control", "no-store");
    return {
      module: "sucursales_real",
      status: "ready",
      timestamp: new Date().toISOString(),
    };
  });

  // GET /sucursales-real (scoped)
  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = PageQuery.safeParse(req.query);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Query inválida", errors: parsed.error.flatten() });
    }

    const { limit, offset, q } = parsed.data;

    try {
      const academiaId = getEffectiveAcademiaId(req);

      let sql = "SELECT id, academia_id, nombre FROM sucursales_real WHERE academia_id = ?";
      const args: any[] = [academiaId];

      if (q) {
        sql += " AND nombre LIKE ? ESCAPE '\\\\'";
        args.push(`%${escapeLike(q)}%`);
      }

      sql += " ORDER BY nombre ASC, id ASC LIMIT ? OFFSET ?";
      args.push(limit, offset);

      const [rows]: any = await db.query(sql, args);

      reply.header("Cache-Control", "no-store");
      return reply.send({
        ok: true,
        items: (rows ?? []).map(normalize),
        limit,
        offset,
        count: rows?.length ?? 0,
      });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al listar sucursales", detail: err?.message });
    }
  });

  // GET /sucursales-real/:id (scoped)
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    try {
      const academiaId = getEffectiveAcademiaId(req);
      const id = parsed.data.id;

      const [rows]: any = await db.query(
        "SELECT id, academia_id, nombre FROM sucursales_real WHERE id = ? AND academia_id = ? LIMIT 1",
        [id, academiaId]
      );

      reply.header("Cache-Control", "no-store");

      if (!rows?.length) return reply.code(404).send({ ok: false, message: "Sucursal no encontrada" });
      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al obtener sucursal", detail: err?.message });
    }
  });

  // POST /sucursales-real (scoped)
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const body = CreateSchema.parse(req.body);
      const nombre = body.nombre.trim();

      const academiaId = getEffectiveAcademiaId(req);

      const [result]: any = await db.query(
        "INSERT INTO sucursales_real (academia_id, nombre) VALUES (?, ?)",
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
        return reply.code(400).send({ ok: false, message: "Datos inválidos", detail });
      }

      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "Ya existe una sucursal con ese nombre en esta academia" });
      }

      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al crear sucursal", detail: err?.message });
    }
  });

  // PUT /sucursales-real/:id (scoped)
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pid = IdParam.safeParse(req.params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    try {
      const body = UpdateSchema.parse(req.body);
      const changes: any = {};
      if (body.nombre !== undefined) changes.nombre = body.nombre.trim();

      if (Object.keys(changes).length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }
      if ("nombre" in changes && !changes.nombre) {
        return reply.code(400).send({ ok: false, field: "nombre", message: "Nombre no puede ser vacío" });
      }

      const academiaId = getEffectiveAcademiaId(req);
      const id = pid.data.id;

      const [result]: any = await db.query(
        "UPDATE sucursales_real SET ? WHERE id = ? AND academia_id = ?",
        [changes, id, academiaId]
      );

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "Sucursal no encontrada" });
      }

      return reply.send({ ok: true, updated: { id, ...changes } });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: "Datos inválidos", detail });
      }

      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "Ya existe una sucursal con ese nombre en esta academia" });
      }

      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al actualizar sucursal", detail: err?.message });
    }
  });

  // DELETE /sucursales-real/:id (scoped)
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    try {
      const academiaId = getEffectiveAcademiaId(req);
      const id = parsed.data.id;

      const [result]: any = await db.query(
        "DELETE FROM sucursales_real WHERE id = ? AND academia_id = ?",
        [id, academiaId]
      );

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "Sucursal no encontrada" });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: hay jugadores vinculados a esta sucursal",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al eliminar sucursal", detail: err?.message });
    }
  });
}
