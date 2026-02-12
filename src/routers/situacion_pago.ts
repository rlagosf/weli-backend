// src/routers/situacion_pago.ts
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: situacion_pago
 * Campos: id (PK), academia_id (INT), nombre (VARCHAR)
 * Uso: catálogo por academia (al día, moroso, becado, etc.)
 * UNIQUE recomendado: (academia_id, nombre)
 */

const IdParam = z.object({ id: z.coerce.number().int().positive() });

const CreateSchema = z
  .object({
    nombre: z
      .string()
      .trim()
      .min(2, "Debe tener al menos 2 caracteres")
      .max(100, "Máximo 100 caracteres"),
  })
  .strict();

// PUT = reemplazo (nombre requerido)
const PutSchema = z
  .object({
    nombre: z
      .string()
      .trim()
      .min(2, "Debe tener al menos 2 caracteres")
      .max(100, "Máximo 100 caracteres"),
  })
  .strict();

// PATCH = parcial
const PatchSchema = z
  .object({
    nombre: z
      .string()
      .trim()
      .min(2, "Debe tener al menos 2 caracteres")
      .max(100, "Máximo 100 caracteres")
      .optional(),
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
  const hdr = (req.headers["x-academia-id"] ?? req.headers["X-Academia-Id"]) as any;
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

async function existsByNombreScoped(academiaId: number, nombre: string, excludeId?: number) {
  const n = String(nombre ?? "").trim();
  if (!n) return false;

  if (excludeId) {
    const [rows]: any = await db.query(
      "SELECT id FROM situacion_pago WHERE academia_id = ? AND LOWER(TRIM(nombre)) = LOWER(?) AND id <> ? LIMIT 1",
      [academiaId, n, excludeId]
    );
    return Array.isArray(rows) && rows.length > 0;
  }

  const [rows]: any = await db.query(
    "SELECT id FROM situacion_pago WHERE academia_id = ? AND LOWER(TRIM(nombre)) = LOWER(?) LIMIT 1",
    [academiaId, n]
  );
  return Array.isArray(rows) && rows.length > 0;
}

export default async function situacion_pago(app: FastifyInstance) {
  // ✅ Catálogo por academia:
  // - READ: roles 1/2/3
  // - WRITE: roles 1/3 (admin + superadmin)
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  app.get("/health", { preHandler: canRead }, async (_req, reply) => {
    reply.header("Cache-Control", "no-store");
    return { module: "situacion_pago", status: "ready", timestamp: new Date().toISOString() };
  });

  // GET /situacion_pago (scoped)
  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academiaId = getEffectiveAcademiaId(req);

      const [rows]: any = await db.query(
        "SELECT id, academia_id, nombre FROM situacion_pago WHERE academia_id = ? ORDER BY nombre ASC, id ASC",
        [academiaId]
      );

      reply.header("Cache-Control", "no-store");
      return reply.send({ ok: true, count: rows?.length ?? 0, items: (rows ?? []).map(normalize) });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al listar situacion_pago", detail: err?.message });
    }
  });

  // GET /situacion_pago/:id (scoped)
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
        "SELECT id, academia_id, nombre FROM situacion_pago WHERE id = ? AND academia_id = ? LIMIT 1",
        [id, academiaId]
      );

      reply.header("Cache-Control", "no-store");
      if (!rows?.length) return reply.code(404).send({ ok: false, message: "Situación de pago no encontrada" });

      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al obtener situacion_pago", detail: err?.message });
    }
  });

  // POST /situacion_pago (scoped)
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const body = CreateSchema.parse(req.body);
      const nombre = body.nombre.trim();
      const academiaId = getEffectiveAcademiaId(req);

      const dup = await existsByNombreScoped(academiaId, nombre);
      if (dup) {
        reply.header("Cache-Control", "no-store");
        return reply.code(409).send({ ok: false, message: "La situación de pago ya existe en esta academia" });
      }

      const [result]: any = await db.query("INSERT INTO situacion_pago (academia_id, nombre) VALUES (?, ?)", [
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
        return reply.code(409).send({ ok: false, message: "La situación de pago ya existe en esta academia" });
      }
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al crear situacion_pago", detail: err?.message });
    }
  });

  // PUT /situacion_pago/:id (reemplazo)
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
        return reply.code(409).send({ ok: false, message: "La situación de pago ya existe en esta academia" });
      }

      const [result]: any = await db.query(
        "UPDATE situacion_pago SET nombre = ? WHERE id = ? AND academia_id = ?",
        [nombre, id, academiaId]
      );

      reply.header("Cache-Control", "no-store");
      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "Situación de pago no encontrada" });
      }

      return reply.send({ ok: true, updated: { id, nombre } });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");
      if (err instanceof ZodError) {
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail: zodDetail(err) });
      }
      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "La situación de pago ya existe en esta academia" });
      }
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al actualizar situacion_pago", detail: err?.message });
    }
  });

  // PATCH /situacion_pago/:id (parcial)
  app.patch("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pid = IdParam.safeParse(req.params);
    if (!pid.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const academiaId = getEffectiveAcademiaId(req);
      const id = pid.data.id;

      const body = PatchSchema.parse(req.body);
      if (Object.keys(body).length === 0) {
        reply.header("Cache-Control", "no-store");
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      if (body.nombre !== undefined) {
        const nombre = body.nombre.trim();

        const dup = await existsByNombreScoped(academiaId, nombre, id);
        if (dup) {
          reply.header("Cache-Control", "no-store");
          return reply.code(409).send({ ok: false, message: "La situación de pago ya existe en esta academia" });
        }

        const [result]: any = await db.query(
          "UPDATE situacion_pago SET nombre = ? WHERE id = ? AND academia_id = ?",
          [nombre, id, academiaId]
        );

        reply.header("Cache-Control", "no-store");
        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({ ok: false, message: "Situación de pago no encontrada" });
        }

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
        return reply.code(409).send({ ok: false, message: "La situación de pago ya existe en esta academia" });
      }
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al actualizar situacion_pago", detail: err?.message });
    }
  });

  // DELETE /situacion_pago/:id (scoped)
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const academiaId = getEffectiveAcademiaId(req);
      const id = parsed.data.id;

      const [result]: any = await db.query("DELETE FROM situacion_pago WHERE id = ? AND academia_id = ?", [
        id,
        academiaId,
      ]);

      reply.header("Cache-Control", "no-store");
      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "Situación de pago no encontrada" });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");
      if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: hay pagos de jugadores vinculados a esta situación de pago.",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      return reply.code(code).send({ ok: false, message: "Error al eliminar situacion_pago", detail: err?.message });
    }
  });
}
