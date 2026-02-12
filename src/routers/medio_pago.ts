// src/routers/medio_pago.ts
import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: medio_pago
 * Campos esperados: id (PK), academia_id (INT), nombre (VARCHAR)
 * Recomendado: UNIQUE(academia_id, nombre)
 */

const IdParam = z.object({ id: z.coerce.number().int().positive() });

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(100, "Máximo 100 caracteres"),
  })
  .strict();

// PUT = reemplazo: nombre requerido
const PutSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(100, "Máximo 100 caracteres"),
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

/* ──────────────────────────────────────────────────────────────
   Multi-academia helpers (WELI) — REGLA PLATINO (búnker)
   - rol 3 (superadmin): x-academia-id OBLIGATORIO (define tenant)
   - rol 1/2 (admin/staff): tenant SOLO desde token (ignora header)
   Lee desde req.auth o req.user (según middleware).
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

function getTokenAcademiaId(req: FastifyRequest): number {
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
  return Number.isFinite(n) ? n : 0;
}

function getHeaderAcademiaId(req: FastifyRequest): number {
  const hdr = (req.headers as any)["x-academia-id"];
  const raw = Array.isArray(hdr) ? hdr[0] : hdr;
  const n = Number(raw);
  return Number.isFinite(n) ? n : 0;
}

function getEffectiveAcademiaId(req: FastifyRequest): number {
  const rol = getRolId(req);

  // ✅ Superadmin: header manda (OBLIGATORIO)
  if (rol === 3) {
    const headerAcademia = getHeaderAcademiaId(req);
    if (!headerAcademia || headerAcademia <= 0) {
      throw Object.assign(new Error("FORBIDDEN: falta x-academia-id para superadmin"), { statusCode: 403 });
    }
    return headerAcademia;
  }

  // ✅ Admin/Staff: SOLO token (búnker)
  const tokenAcademia = getTokenAcademiaId(req);
  if (!tokenAcademia || tokenAcademia <= 0) {
    throw Object.assign(new Error("FORBIDDEN: token sin academia_id"), { statusCode: 403 });
  }
  return tokenAcademia;
}

async function existsByNombreScoped(academiaId: number, nombre: string, excludeId?: number) {
  const n = String(nombre ?? "").trim();
  if (!n) return false;

  if (excludeId) {
    const [rows]: any = await db.query(
      "SELECT id FROM medio_pago WHERE academia_id = ? AND LOWER(TRIM(nombre)) = LOWER(?) AND id <> ? LIMIT 1",
      [academiaId, n, excludeId]
    );
    return Array.isArray(rows) && rows.length > 0;
  }

  const [rows]: any = await db.query(
    "SELECT id FROM medio_pago WHERE academia_id = ? AND LOWER(TRIM(nombre)) = LOWER(?) LIMIT 1",
    [academiaId, n]
  );
  return Array.isArray(rows) && rows.length > 0;
}

export default async function medio_pago(app: FastifyInstance) {
  // ✅ Catálogo scoped por academia:
  // - READ: roles 1/2/3
  // - WRITE: roles 1/3
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  app.get("/health", { preHandler: canRead }, async (_req, reply) => {
    reply.header("Cache-Control", "no-store");
    return { module: "medio_pago", status: "ready", timestamp: new Date().toISOString() };
  });

  // GET /medio_pago (scoped)
  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academiaId = getEffectiveAcademiaId(req);

      const [rows]: any = await db.query(
        "SELECT id, academia_id, nombre FROM medio_pago WHERE academia_id = ? ORDER BY nombre ASC, id ASC",
        [academiaId]
      );

      reply.header("Cache-Control", "no-store");
      return reply.send({
        ok: true,
        count: rows?.length ?? 0,
        items: (rows ?? []).map(normalize),
      });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al listar medio_pago", detail: err?.message });
    }
  });

  // GET /medio_pago/:id (scoped)
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    try {
      const academiaId = getEffectiveAcademiaId(req);
      const id = parsed.data.id;

      const [rows]: any = await db.query(
        "SELECT id, academia_id, nombre FROM medio_pago WHERE id = ? AND academia_id = ? LIMIT 1",
        [id, academiaId]
      );

      reply.header("Cache-Control", "no-store");
      if (!rows?.length) return reply.code(404).send({ ok: false, message: "Medio de pago no encontrado" });

      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al obtener medio_pago", detail: err?.message });
    }
  });

  // POST /medio_pago (scoped)
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const body = CreateSchema.parse(req.body);
      const nombre = body.nombre.trim();
      const academiaId = getEffectiveAcademiaId(req);

      const dup = await existsByNombreScoped(academiaId, nombre);
      if (dup) return reply.code(409).send({ ok: false, message: "El medio de pago ya existe en esta academia" });

      const [result]: any = await db.query("INSERT INTO medio_pago (academia_id, nombre) VALUES (?, ?)", [
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
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail: zodDetail(err) });
      }
      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "El medio de pago ya existe en esta academia" });
      }
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al crear medio_pago", detail: err?.message });
    }
  });

  // PUT /medio_pago/:id (scoped)
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pid = IdParam.safeParse(req.params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    try {
      const academiaId = getEffectiveAcademiaId(req);
      const id = pid.data.id;

      const body = PutSchema.parse(req.body);
      const nombre = body.nombre.trim();

      const dup = await existsByNombreScoped(academiaId, nombre, id);
      if (dup) return reply.code(409).send({ ok: false, message: "El medio de pago ya existe en esta academia" });

      const [result]: any = await db.query(
        "UPDATE medio_pago SET nombre = ? WHERE id = ? AND academia_id = ?",
        [nombre, id, academiaId]
      );

      reply.header("Cache-Control", "no-store");
      if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, updated: { id, nombre } });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");
      if (err instanceof ZodError) {
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail: zodDetail(err) });
      }
      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "El medio de pago ya existe en esta academia" });
      }
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al actualizar medio_pago", detail: err?.message });
    }
  });

  // DELETE /medio_pago/:id (scoped)
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    try {
      const academiaId = getEffectiveAcademiaId(req);
      const id = parsed.data.id;

      const [result]: any = await db.query("DELETE FROM medio_pago WHERE id = ? AND academia_id = ?", [id, academiaId]);

      reply.header("Cache-Control", "no-store");
      if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");
      if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: el medio de pago está siendo usado",
          detail: err?.sqlMessage ?? err?.message,
        });
      }
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al eliminar medio_pago", detail: err?.message });
    }
  });
}
