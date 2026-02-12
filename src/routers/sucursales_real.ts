// src/routers/sucursalesReal.ts
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
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
    nombre: z
      .string()
      .trim()
      .min(3, "El nombre debe tener al menos 3 caracteres")
      .max(100, "Máximo 100 caracteres"),
  })
  .strict();

// PUT = reemplazo (nombre requerido)
const PutSchema = z
  .object({
    nombre: z
      .string()
      .trim()
      .min(3, "El nombre debe tener al menos 3 caracteres")
      .max(100, "Máximo 100 caracteres"),
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

function zodDetail(err: ZodError) {
  return err.issues.map((i) => `${i.path.join(".") || "field"}: ${i.message}`).join("; ");
}

/* ──────────────────────────────────────────────────────────────
   Multi-academia helpers (WELI) — ESTÁNDAR ÚNICO
   Regla:
   - rol 1/2: academia_id desde token (req.auth o req.user)
   - rol 3: academia_id desde header x-academia-id (obligatorio)
────────────────────────────────────────────────────────────── */

type AuthLike = {
  rol_id?: number;
  role_id?: number;
  role?: number;
  academia_id?: number;
  academy_id?: number;
  academiaId?: number;
  academyId?: number;
  academia?: number;
  academy?: number;
};

function getAuthLike(req: FastifyRequest): AuthLike {
  const a: any = (req as any).auth;
  const u: any = (req as any).user;
  return (a && typeof a === "object" ? a : u && typeof u === "object" ? u : {}) as AuthLike;
}

function getRolId(req: FastifyRequest): number {
  const ctx = getAuthLike(req);
  const raw = ctx.rol_id ?? ctx.role_id ?? ctx.role ?? 0;
  const n = Number(raw);
  return Number.isFinite(n) ? n : 0;
}

function getHeaderAcademiaId(req: FastifyRequest): number {
  const hdr = (req.headers["x-academia-id"] ?? (req.headers as any)["X-Academia-Id"]) as any;
  const raw = Array.isArray(hdr) ? hdr[0] : hdr;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    throw Object.assign(new Error("FORBIDDEN: falta x-academia-id para superadmin"), { statusCode: 403 });
  }
  return n;
}

function getEffectiveAcademiaId(req: FastifyRequest): number {
  const rol = getRolId(req);

  if (rol === 3) {
    return getHeaderAcademiaId(req);
  }

  const ctx = getAuthLike(req);
  const raw =
    ctx.academia_id ??
    ctx.academy_id ??
    ctx.academiaId ??
    ctx.academyId ??
    ctx.academia ??
    ctx.academy ??
    0;

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

async function existsByNombreScoped(academiaId: number, nombre: string, excludeId?: number) {
  const n = String(nombre ?? "").trim();
  if (!n) return false;

  if (excludeId) {
    const [rows]: any = await db.query(
      "SELECT id FROM sucursales_real WHERE academia_id = ? AND LOWER(TRIM(nombre)) = LOWER(?) AND id <> ? LIMIT 1",
      [academiaId, n, excludeId]
    );
    return Array.isArray(rows) && rows.length > 0;
  }

  const [rows]: any = await db.query(
    "SELECT id FROM sucursales_real WHERE academia_id = ? AND LOWER(TRIM(nombre)) = LOWER(?) LIMIT 1",
    [academiaId, n]
  );
  return Array.isArray(rows) && rows.length > 0;
}

export default async function sucursales_real(app: FastifyInstance) {
  // ✅ Catálogo por academia:
  // - READ: roles 1/2/3
  // - WRITE: roles 1/3 (admin + superadmin)
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  app.get("/health", { preHandler: canRead }, async (_req, reply) => {
    reply.header("Cache-Control", "no-store");
    return { module: "sucursales_real", status: "ready", timestamp: new Date().toISOString() };
  });

  // GET /sucursales-real (scoped + paginado + filtro)
  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = PageQuery.safeParse(req.query);
    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "Query inválida", errors: parsed.error.flatten() });
    }

    const { limit, offset, q } = parsed.data;

    try {
      const academiaId = getEffectiveAcademiaId(req);

      let where = "WHERE academia_id = ?";
      const args: any[] = [academiaId];

      if (q) {
        where += " AND nombre LIKE ? ESCAPE '\\\\'";
        args.push(`%${escapeLike(q)}%`);
      }

      const [rows]: any = await db.query(
        `SELECT id, academia_id, nombre
           FROM sucursales_real
           ${where}
           ORDER BY nombre ASC, id ASC
           LIMIT ? OFFSET ?`,
        [...args, limit, offset]
      );

      const [countRows]: any = await db.query(
        `SELECT COUNT(*) AS total
           FROM sucursales_real
           ${where}`,
        args
      );

      const total = Number(countRows?.[0]?.total ?? 0);

      reply.header("Cache-Control", "no-store");
      return reply.send({
        ok: true,
        items: (rows ?? []).map(normalize),
        limit,
        offset,
        count: rows?.length ?? 0,
        total,
      });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al listar sucursales", detail: err?.message });
    }
  });

  // GET /sucursales-real/:id (scoped)
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

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
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al obtener sucursal", detail: err?.message });
    }
  });

  // POST /sucursales-real (scoped)
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const body = CreateSchema.parse(req.body);
      const nombre = body.nombre.trim();
      const academiaId = getEffectiveAcademiaId(req);

      const dup = await existsByNombreScoped(academiaId, nombre);
      if (dup) {
        reply.header("Cache-Control", "no-store");
        return reply.code(409).send({ ok: false, message: "Ya existe una sucursal con ese nombre en esta academia" });
      }

      const [result]: any = await db.query("INSERT INTO sucursales_real (academia_id, nombre) VALUES (?, ?)", [
        academiaId,
        nombre,
      ]);

      reply.header("Cache-Control", "no-store");
      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        item: { id: result.insertId, academia_id: academiaId, nombre },
      });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");
      if (err instanceof ZodError) {
        return reply.code(400).send({ ok: false, message: "Datos inválidos", detail: zodDetail(err) });
      }
      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "Ya existe una sucursal con ese nombre en esta academia" });
      }
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al crear sucursal", detail: err?.message });
    }
  });

  // PUT /sucursales-real/:id (scoped, reemplazo)
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pid = IdParam.safeParse(req.params);
    if (!pid.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const academiaId = getEffectiveAcademiaId(req);
      const id = pid.data.id;

      const body = PutSchema.parse(req.body);
      const nombre = body.nombre.trim();

      const dup = await existsByNombreScoped(academiaId, nombre, id);
      if (dup) {
        reply.header("Cache-Control", "no-store");
        return reply.code(409).send({ ok: false, message: "Ya existe una sucursal con ese nombre en esta academia" });
      }

      const [result]: any = await db.query(
        "UPDATE sucursales_real SET nombre = ? WHERE id = ? AND academia_id = ?",
        [nombre, id, academiaId]
      );

      reply.header("Cache-Control", "no-store");
      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "Sucursal no encontrada" });
      }

      return reply.send({ ok: true, updated: { id, nombre } });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");
      if (err instanceof ZodError) {
        return reply.code(400).send({ ok: false, message: "Datos inválidos", detail: zodDetail(err) });
      }
      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "Ya existe una sucursal con ese nombre en esta academia" });
      }
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al actualizar sucursal", detail: err?.message });
    }
  });

  // DELETE /sucursales-real/:id (scoped)
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const academiaId = getEffectiveAcademiaId(req);
      const id = parsed.data.id;

      const [result]: any = await db.query("DELETE FROM sucursales_real WHERE id = ? AND academia_id = ?", [
        id,
        academiaId,
      ]);

      reply.header("Cache-Control", "no-store");
      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "Sucursal no encontrada" });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");
      if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: hay registros asociados a esta sucursal",
          detail: err?.sqlMessage ?? err?.message,
        });
      }
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al eliminar sucursal", detail: err?.message });
    }
  });
}
