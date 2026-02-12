// src/routers/eventos.ts
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: eventos
 *  id, academia_id, titulo, descripcion, fecha_inicio, fecha_fin, creado_en, actualizado_en
 */

/* ───────────────────────── ZOD ───────────────────────── */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z.object({
  titulo: z.string().trim().min(1).max(200),
  descripcion: z.string().trim().max(2000).optional().nullable(),
  fecha_inicio: z.string().min(10),
  fecha_fin: z.string().min(10),
});

const UpdateSchema = z.object({
  titulo: z.string().trim().min(1).max(200).optional(),
  descripcion: z.string().trim().max(2000).optional().nullable(),
  fecha_inicio: z.string().min(10).optional(),
  fecha_fin: z.string().min(10).optional(),
});

const PageQuery = z.object({
  limit: z.coerce.number().int().positive().max(200).default(50),
  offset: z.coerce.number().int().nonnegative().default(0),
});

/* ───────────────────────── Helpers ───────────────────────── */

// Normaliza fecha de ISO o 'YYYY-MM-DD HH:MM:SS' a 'YYYY-MM-DD HH:MM:SS'
function toSQLDateTime(input: string): string | null {
  if (!input) return null;
  const s = String(input).trim();
  if (!s) return null;

  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)) return s;

  const d = new Date(s);
  if (Number.isNaN(d.valueOf())) return null;

  const pad = (n: number) => String(n).padStart(2, "0");
  const yyyy = d.getFullYear();
  const mm = pad(d.getMonth() + 1);
  const dd = pad(d.getDate());
  const HH = pad(d.getHours());
  const MM = pad(d.getMinutes());
  const SS = pad(d.getSeconds());
  return `${yyyy}-${mm}-${dd} ${HH}:${MM}:${SS}`;
}

// En formato fijo "YYYY-MM-DD HH:MM:SS", comparación lexicográfica funciona
function isEndAfterStart(sqlStart: string, sqlEnd: string): boolean {
  return sqlEnd > sqlStart;
}

function sendDbError(reply: FastifyReply, message: string, err: any) {
  return reply.code(500).send({
    ok: false,
    message,
    error: err?.sqlMessage || err?.message || String(err),
    errno: err?.errno,
    code: err?.code,
  });
}

/* ──────────────────────────────────────────────────────────────
   Multi-academia helpers (WELI) — REGLA PLATINO (igual a categorias/histórico)
   - rol 1/2: academia desde token (req.auth o req.user)
   - rol 3: academia desde header x-academia-id (OBLIGATORIO)
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

function getEffectiveAcademiaId(req: FastifyRequest): number {
  const rol = getRolId(req);

  // rol 3 => header obligatorio
  if (rol === 3) {
    const hdr = (req.headers as any)["x-academia-id"];
    const raw = Array.isArray(hdr) ? hdr[0] : hdr;
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0) {
      throw Object.assign(new Error("FORBIDDEN: falta x-academia-id para superadmin"), {
        statusCode: 403,
      });
    }
    return n;
  }

  // rol 1/2 => token
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

/* ───────────────────────── Router ───────────────────────── */

export default async function eventos(app: FastifyInstance) {
  // ✅ Mantener roles como están
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  app.get("/health", { preHandler: canRead }, async () => ({
    module: "eventos",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // ✅ Público (solo lectura): próximos eventos (GLOBAL, sin academia)
  app.get("/public", async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = PageQuery.safeParse(req.query);
    const { limit, offset } = parsed.success ? parsed.data : { limit: 50, offset: 0 };

    try {
      const [rows]: any = await db.query(
        `SELECT id, titulo, descripcion, fecha_inicio, fecha_fin, creado_en, actualizado_en
           FROM eventos
          WHERE fecha_fin >= NOW()
          ORDER BY fecha_inicio ASC, id ASC
          LIMIT ? OFFSET ?`,
        [Number(limit), Number(offset)]
      );

      reply.header("Cache-Control", "no-store");
      return reply.send({ ok: true, items: rows ?? [], limit, offset });
    } catch (err: any) {
      req.log.error({ err }, "GET /eventos/public failed");
      return sendDbError(reply, "Error al listar eventos públicos", err);
    }
  });

  // GET /eventos (scoped por academia efectiva)
  app.get("/", { preHandler: canRead }, async (req, reply) => {
    try {
      const academiaId = getEffectiveAcademiaId(req);

      const parsed = PageQuery.safeParse(req.query);
      const { limit, offset } = parsed.success ? parsed.data : { limit: 50, offset: 0 };

      const [rows]: any = await db.query(
        `SELECT id, academia_id, titulo, descripcion, fecha_inicio, fecha_fin, creado_en, actualizado_en
           FROM eventos
          WHERE academia_id = ?
          ORDER BY fecha_inicio DESC, id DESC
          LIMIT ? OFFSET ?`,
        [academiaId, Number(limit), Number(offset)]
      );

      reply.header("Cache-Control", "no-store");
      return reply.send({ ok: true, items: rows ?? [], limit, offset, academia_id: academiaId });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      if (code !== 500) return reply.code(code).send({ ok: false, message: err?.message });
      req.log.error({ err }, "GET /eventos failed");
      return sendDbError(reply, "Error al listar eventos", err);
    }
  });

  // GET /eventos/:id (scoped por academia efectiva)
  app.get("/:id", { preHandler: canRead }, async (req, reply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const { id } = parsed.data;

    try {
      const academiaId = getEffectiveAcademiaId(req);

      const [rows]: any = await db.query(
        `SELECT id, academia_id, titulo, descripcion, fecha_inicio, fecha_fin, creado_en, actualizado_en
           FROM eventos
          WHERE id = ? AND academia_id = ?
          LIMIT 1`,
        [id, academiaId]
      );

      reply.header("Cache-Control", "no-store");
      if (!rows?.length) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, item: rows[0], academia_id: academiaId });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      if (code !== 500) return reply.code(code).send({ ok: false, message: err?.message });
      req.log.error({ err, id }, "GET /eventos/:id failed");
      return sendDbError(reply, "Error al obtener evento", err);
    }
  });

  // POST /eventos (write 1/3, inserta academia efectiva)
  app.post("/", { preHandler: canWrite }, async (req, reply) => {
    const parsed = CreateSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Payload inválido", errors: parsed.error.flatten() });
    }

    const { titulo, descripcion, fecha_inicio, fecha_fin } = parsed.data;

    const ini = toSQLDateTime(fecha_inicio);
    const fin = toSQLDateTime(fecha_fin);

    if (!ini || !fin) return reply.code(400).send({ ok: false, message: "Formato de fecha inválido" });
    if (!isEndAfterStart(ini, fin)) {
      return reply.code(400).send({ ok: false, message: "fecha_fin debe ser mayor que fecha_inicio" });
    }

    try {
      const academiaId = getEffectiveAcademiaId(req);

      const [result]: any = await db.query(
        `INSERT INTO eventos (academia_id, titulo, descripcion, fecha_inicio, fecha_fin, creado_en, actualizado_en)
         VALUES (?, ?, ?, ?, ?, NOW(), NOW())`,
        [academiaId, titulo, descripcion ?? null, ini, fin]
      );

      const id = result.insertId;

      const [rows]: any = await db.query(
        `SELECT id, academia_id, titulo, descripcion, fecha_inicio, fecha_fin, creado_en, actualizado_en
           FROM eventos
          WHERE id = ? AND academia_id = ?
          LIMIT 1`,
        [id, academiaId]
      );

      reply.header("Cache-Control", "no-store");
      return reply.code(201).send({ ok: true, item: rows?.[0] ?? null, academia_id: academiaId });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      if (code !== 500) return reply.code(code).send({ ok: false, message: err?.message });
      req.log.error({ err }, "POST /eventos failed");
      return sendDbError(reply, "Error al crear evento", err);
    }
  });

  // PUT /eventos/:id (write 1/3, update por academia efectiva)
  app.put("/:id", { preHandler: canWrite }, async (req, reply) => {
    const pid = IdParam.safeParse(req.params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });
    const { id } = pid.data;

    const parsed = UpdateSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Payload inválido", errors: parsed.error.flatten() });
    }

    const fields: string[] = [];
    const values: any[] = [];

    if (parsed.data.titulo !== undefined) {
      fields.push("titulo = ?");
      values.push(parsed.data.titulo.trim());
    }
    if (parsed.data.descripcion !== undefined) {
      fields.push("descripcion = ?");
      values.push(parsed.data.descripcion?.trim() ?? null);
    }

    let iniTmp: string | null = null;
    let finTmp: string | null = null;

    if (parsed.data.fecha_inicio !== undefined) {
      const ini = toSQLDateTime(parsed.data.fecha_inicio);
      if (!ini) return reply.code(400).send({ ok: false, message: "fecha_inicio inválida" });
      iniTmp = ini;
      fields.push("fecha_inicio = ?");
      values.push(ini);
    }

    if (parsed.data.fecha_fin !== undefined) {
      const fin = toSQLDateTime(parsed.data.fecha_fin);
      if (!fin) return reply.code(400).send({ ok: false, message: "fecha_fin inválida" });
      finTmp = fin;
      fields.push("fecha_fin = ?");
      values.push(fin);
    }

    if (fields.length === 0) return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
    if (iniTmp && finTmp && !isEndAfterStart(iniTmp, finTmp)) {
      return reply.code(400).send({ ok: false, message: "fecha_fin debe ser mayor que fecha_inicio" });
    }

    try {
      const academiaId = getEffectiveAcademiaId(req);

      // Si viene solo una fecha, valida contra la otra existente dentro del mismo tenant
      if (iniTmp || finTmp) {
        const [rowsPrev]: any = await db.query(
          `SELECT fecha_inicio, fecha_fin
             FROM eventos
            WHERE id = ? AND academia_id = ?
            LIMIT 1`,
          [id, academiaId]
        );
        if (!rowsPrev?.length) return reply.code(404).send({ ok: false, message: "No encontrado" });

        const prevIni = String(rowsPrev[0].fecha_inicio);
        const prevFin = String(rowsPrev[0].fecha_fin);

        const finalIni = iniTmp ?? prevIni;
        const finalFin = finTmp ?? prevFin;

        if (!isEndAfterStart(finalIni, finalFin)) {
          return reply.code(400).send({ ok: false, message: "fecha_fin debe ser mayor que fecha_inicio" });
        }
      }

      const sql = `
        UPDATE eventos
           SET ${fields.join(", ")},
               actualizado_en = NOW()
         WHERE id = ? AND academia_id = ?
         LIMIT 1
      `;
      values.push(id, academiaId);

      const [result]: any = await db.query(sql, values);
      if (!result?.affectedRows) return reply.code(404).send({ ok: false, message: "No encontrado" });

      const [rows]: any = await db.query(
        `SELECT id, academia_id, titulo, descripcion, fecha_inicio, fecha_fin, creado_en, actualizado_en
           FROM eventos
          WHERE id = ? AND academia_id = ?
          LIMIT 1`,
        [id, academiaId]
      );

      reply.header("Cache-Control", "no-store");
      return reply.send({ ok: true, item: rows?.[0] ?? null, academia_id: academiaId });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      if (code !== 500) return reply.code(code).send({ ok: false, message: err?.message });
      req.log.error({ err, id }, "PUT /eventos/:id failed");
      return sendDbError(reply, "Error al actualizar evento", err);
    }
  });

  // DELETE /eventos/:id (write 1/3, delete por academia efectiva)
  app.delete("/:id", { preHandler: canWrite }, async (req, reply) => {
    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const { id } = parsed.data;

    try {
      const academiaId = getEffectiveAcademiaId(req);

      const [result]: any = await db.query(
        "DELETE FROM eventos WHERE id = ? AND academia_id = ? LIMIT 1",
        [id, academiaId]
      );

      if (!result?.affectedRows) return reply.code(404).send({ ok: false, message: "No encontrado" });

      reply.header("Cache-Control", "no-store");
      return reply.send({ ok: true, deleted: id, academia_id: academiaId });
    } catch (err: any) {
      if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: el evento está asociado a otros registros",
          error: err?.sqlMessage || err?.message,
        });
      }

      req.log.error({ err, id }, "DELETE /eventos/:id failed");
      return sendDbError(reply, "Error al eliminar evento", err);
    }
  });
}
