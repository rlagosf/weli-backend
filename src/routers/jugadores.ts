// src/routers/jugadores.ts
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { ensureApoderadoAuth } from "../scripts/hash_apoderado";
import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * ───────────────────────────────
 * Helpers FOTO / PDF (validación liviana)
 * ───────────────────────────────
 */
function isValidMime(m?: string) {
  return ["image/jpeg", "image/jpg", "image/png", "image/webp"].includes(
    String(m || "")
      .toLowerCase()
      .trim()
  );
}

function isValidPdfMime(m?: string) {
  const mm = String(m || "")
    .toLowerCase()
    .trim();
  return mm === "application/pdf";
}

function cleanBase64Payload(input: string) {
  const s = String(input || "").trim();
  const idx = s.indexOf("base64,");
  if (s.startsWith("data:") && idx !== -1) return s.slice(idx + "base64,".length);
  return s;
}

function normalizeB64(input: string) {
  return String(input || "")
    .replace(/\s+/g, "")
    .trim();
}

function looksLikeBase64(b64: string) {
  const s = normalizeB64(b64);
  if (!s) return false;
  return /^[A-Za-z0-9+/]+={0,2}$/.test(s);
}

function approxBytesFromBase64(b64: string) {
  const s = normalizeB64(b64);
  const padding = s.endsWith("==") ? 2 : s.endsWith("=") ? 1 : 0;
  return Math.floor((s.length * 3) / 4) - padding;
}

/**
 * ───────────────────────────────
 * Helpers DB: obtener conexión transaccional segura
 * ───────────────────────────────
 */
async function getConn() {
  const anyDb: any = db as any;
  if (typeof anyDb.getConnection === "function") {
    const conn = await anyDb.getConnection();
    return { conn, release: () => conn.release?.() };
  }
  return { conn: anyDb, release: () => {} };
}

/**
 * ───────────────────────────────
 * Contexto de academia
 * ───────────────────────────────
 * La resolución del tenant se centraliza en authz.ts mediante
 * getEffectiveAcademiaId(req).
 */

async function resolveAcademiaContext(conn: any, academiaId: number) {
  const [rows]: any = await conn.query("SELECT id, deporte_id FROM academias WHERE id = ? LIMIT 1", [academiaId]);

  if (!rows || rows.length === 0) {
    throw Object.assign(new Error("Academia no existe (tenant inválido)"), { statusCode: 409 });
  }

  const deporteId = Number(rows[0]?.deporte_id ?? 0);
  if (!Number.isFinite(deporteId) || deporteId <= 0) {
    throw Object.assign(new Error("Academia sin deporte_id configurado"), { statusCode: 409 });
  }

  return { academia_id: academiaId, deporte_id: deporteId };
}

/**
 * jugadores.estadistica_id es UNIQUE y FK -> estadisticas.estadistica_id
 */

// ───────── Schemas ─────────
const IdParam = z.object({
  id: z.string().regex(/^\d+$/, "ID inválido"),
});

const RutParam = z.object({
  rut: z.string().regex(/^\d{7,8}$/, "El RUT debe tener 7 u 8 dígitos (sin DV)"),
});

const PageQuery = z.object({
  limit: z.coerce.number().int().positive().max(200).default(100),
  offset: z.coerce.number().int().nonnegative().default(0),
  q: z.string().trim().min(1).max(100).optional(),
  include_inactivos: z.coerce.number().int().optional().default(0),
});

const BaseFields = {
  nombre_jugador: z.string().trim().min(1).optional(),
  rut_jugador: z.union([z.string().regex(/^\d{7,8}$/), z.number().int().min(1)]).optional(),
  email: z.string().email().optional(),
  telefono: z.string().trim().min(3).optional(),

  edad: z.union([z.number().int(), z.string().regex(/^\d+$/)]).optional(),
  peso: z.union([z.number(), z.string().regex(/^\d+(\.\d+)?$/)]).optional(),
  estatura: z.union([z.number(), z.string().regex(/^\d+(\.\d+)?$/)]).optional(),

  talla_polera: z.string().trim().optional(),
  talla_short: z.string().trim().optional(),
  nombre_apoderado: z.string().trim().optional(),
  rut_apoderado: z.union([z.string().regex(/^\d{7,8}$/), z.number().int().min(1)]).optional(),
  telefono_apoderado: z.string().trim().optional(),

  posicion_id: z.union([z.number().int(), z.string().regex(/^\d+$/)]).optional(),
  categoria_id: z.union([z.number().int(), z.string().regex(/^\d+$/)]).optional(),
  establec_educ_id: z.union([z.number().int(), z.string().regex(/^\d+$/)]).optional(),
  prevision_medica_id: z.union([z.number().int(), z.string().regex(/^\d+$/)]).optional(),
  estado_id: z.union([z.number().int(), z.string().regex(/^\d+$/)]).optional(),

  direccion: z.string().trim().optional(),
  comuna_id: z.union([z.number().int(), z.string().regex(/^\d+$/)]).optional(),

  observaciones: z.string().trim().optional(),
  fecha_nacimiento: z.union([z.string(), z.date()]).optional(),

  sucursal_id: z
    .union([z.number().int(), z.string().regex(/^\d+$/)])
    .nullable()
    .optional(),

  foto_base64: z.string().trim().nullable().optional(),
  foto_mime: z.string().trim().nullable().optional(),

  contrato_prestacion: z.string().trim().nullable().optional(),
  contrato_prestacion_mime: z.string().trim().nullable().optional(),
  contrato_prestacion_updated_at: z.union([z.string(), z.date()]).nullable().optional(),
};

const CreateSchema = z
  .object({
    ...BaseFields,
    nombre_jugador: z.string().trim().min(1),
    rut_jugador: z.union([z.string().regex(/^\d{7,8}$/), z.number().int().min(1)]),

    // Compatibilidad legacy: clientes antiguos todavía pueden enviar sucursal_id.
    sucursal_id: z
      .union([z.number().int(), z.string().regex(/^\d+$/)])
      .nullable()
      .optional(),

    // Nuevo modelo: una o muchas sucursales.
    sucursales: z
      .array(z.union([z.number().int().positive(), z.string().regex(/^\d+$/)]))
      .min(1, "Debes seleccionar al menos una sucursal")
      .max(50, "No puedes seleccionar más de 50 sucursales")
      .optional(),
  })
  .strict()
  .superRefine((data, ctx) => {
    const hasLegacy = data.sucursal_id !== null && data.sucursal_id !== undefined;
    const hasMany = Array.isArray(data.sucursales) && data.sucursales.length > 0;

    if (!hasLegacy && !hasMany) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sucursales"],
        message: "Debes seleccionar al menos una sucursal",
      });
    }
  });

const UpdateSchema = z.object({ ...BaseFields }).strict();

const allowedKeys = new Set([
  "nombre_jugador",
  "rut_jugador",
  "email",
  "telefono",
  "edad",
  "peso",
  "estatura",
  "talla_polera",
  "talla_short",
  "nombre_apoderado",
  "rut_apoderado",
  "telefono_apoderado",
  "posicion_id",
  "categoria_id",
  "establec_educ_id",
  "prevision_medica_id",
  "estado_id",
  "direccion",
  "comuna_id",
  "observaciones",
  "fecha_nacimiento",
  "sucursal_id",

  "foto_base64",
  "foto_mime",

  "contrato_prestacion",
  "contrato_prestacion_mime",
  "contrato_prestacion_updated_at",
]);

function pickAllowed(body: Record<string, any>) {
  const out: Record<string, any> = {};
  for (const k in body) {
    if (allowedKeys.has(k)) out[k] = body[k];
  }
  return out;
}

function coerceForDB(row: Record<string, any>) {
  const out: Record<string, any> = { ...row };

  const asInt = [
    "edad",
    "posicion_id",
    "categoria_id",
    "establec_educ_id",
    "prevision_medica_id",
    "estado_id",
    "rut_jugador",
    "rut_apoderado",
    "sucursal_id",
    "comuna_id",
  ];

  for (const k of asInt) {
    if (k in out && out[k] !== null && out[k] !== undefined && out[k] !== "") {
      const n = Number.parseInt(String(out[k]), 10);
      out[k] = Number.isNaN(n) ? null : n;
    }
  }

  const asFloat = ["peso", "estatura"];
  for (const k of asFloat) {
    if (k in out && out[k] !== null && out[k] !== undefined && out[k] !== "") {
      const n = Number.parseFloat(String(out[k]));
      out[k] = Number.isNaN(n) ? null : n;
    }
  }

  if (typeof out.fecha_nacimiento === "string" || out.fecha_nacimiento instanceof Date) {
    const d = new Date(out.fecha_nacimiento);
    if (!Number.isNaN(d.getTime())) {
      const y = d.getUTCFullYear();
      const m = String(d.getUTCMonth() + 1).padStart(2, "0");
      const da = String(d.getUTCDate()).padStart(2, "0");
      out.fecha_nacimiento = `${y}-${m}-${da}`;
    } else if (typeof out.fecha_nacimiento === "string" && /^\d{4}-\d{2}-\d{2}$/.test(out.fecha_nacimiento)) {
      // ok
    } else {
      delete out.fecha_nacimiento;
    }
  }

  if (typeof out.email === "string") out.email = out.email.trim().toLowerCase();

  for (const k of Object.keys(out)) {
    if (out[k] === "") out[k] = null;
  }

  if (typeof out.foto_base64 === "string") out.foto_base64 = cleanBase64Payload(out.foto_base64);
  if (typeof out.contrato_prestacion === "string")
    out.contrato_prestacion = cleanBase64Payload(out.contrato_prestacion);

  if (typeof out.contrato_prestacion_updated_at === "string" || out.contrato_prestacion_updated_at instanceof Date) {
    const d = new Date(out.contrato_prestacion_updated_at);
    if (!Number.isNaN(d.getTime())) out.contrato_prestacion_updated_at = d;
    else delete out.contrato_prestacion_updated_at;
  }

  delete (out as any).estadistica_id;
  return out;
}

function normalizeListOut(row: any) {
  if (!row) return null;
  return {
    id: Number(row.id),
    academia_id: row.academia_id != null ? Number(row.academia_id) : null,
    deporte_id: row.deporte_id != null ? Number(row.deporte_id) : null,

    rut_jugador: row.rut_jugador != null ? Number(row.rut_jugador) : null,
    nombre_jugador: String(row.nombre_jugador ?? ""),
    edad: row.edad != null ? Number(row.edad) : null,
    email: row.email ?? null,
    telefono: row.telefono ?? null,
    peso: row.peso != null ? Number(row.peso) : null,
    estatura: row.estatura != null ? Number(row.estatura) : null,
    talla_polera: row.talla_polera ?? null,
    talla_short: row.talla_short ?? null,
    nombre_apoderado: row.nombre_apoderado ?? null,
    rut_apoderado: row.rut_apoderado != null ? Number(row.rut_apoderado) : null,
    telefono_apoderado: row.telefono_apoderado ?? null,
    posicion_id: row.posicion_id != null ? Number(row.posicion_id) : null,
    categoria_id: row.categoria_id != null ? Number(row.categoria_id) : null,
    establec_educ_id: row.establec_educ_id != null ? Number(row.establec_educ_id) : null,
    prevision_medica_id: row.prevision_medica_id != null ? Number(row.prevision_medica_id) : null,
    estado_id: row.estado_id != null ? Number(row.estado_id) : null,
    direccion: row.direccion ?? null,
    comuna_id: row.comuna_id != null ? Number(row.comuna_id) : null,
    observaciones: row.observaciones ?? null,
    fecha_nacimiento: row.fecha_nacimiento ?? null,
    estadistica_id: row.estadistica_id != null ? Number(row.estadistica_id) : null,
    sucursal_id: row.sucursal_id != null ? Number(row.sucursal_id) : null,

    foto_mime: row.foto_mime ?? null,
    foto_updated_at: row.foto_updated_at ?? null,

    contrato_prestacion_mime: row.contrato_prestacion_mime ?? null,
    contrato_prestacion_updated_at: row.contrato_prestacion_updated_at ?? null,
  };
}

function normalizeDetailOut(row: any) {
  if (!row) return null;
  const base = normalizeListOut(row);
  return {
    ...base,
    foto_base64: row.foto_base64 ?? null,
    contrato_prestacion: row.contrato_prestacion ?? null,
  };
}

function applyFotoRules(target: Record<string, any>) {
  const hasAny = target.foto_base64 != null || target.foto_mime != null;
  if (!hasAny) return;

  const b64Raw = target.foto_base64;
  const mimeRaw = target.foto_mime;

  const wantsClear =
    (b64Raw === null || b64Raw === undefined || b64Raw === "") &&
    (mimeRaw === null || mimeRaw === undefined || mimeRaw === "");

  if (wantsClear) {
    target.foto_base64 = null;
    target.foto_mime = null;
    (target as any).foto_updated_at = new Date();
    return;
  }

  const b64 = normalizeB64(cleanBase64Payload(String(b64Raw || "")));
  const mime = String(mimeRaw || "")
    .toLowerCase()
    .trim();

  if (!mime || !isValidMime(mime)) throw Object.assign(new Error("foto_mime inválido"), { statusCode: 400 });
  if (!b64 || !looksLikeBase64(b64)) throw Object.assign(new Error("foto_base64 inválido"), { statusCode: 400 });

  const bytes = approxBytesFromBase64(b64);
  const MAX_BYTES = 350 * 1024;
  if (bytes > MAX_BYTES)
    throw Object.assign(new Error(`Foto excede el máximo (${MAX_BYTES} bytes)`), { statusCode: 413 });

  target.foto_base64 = b64;
  target.foto_mime = mime;
  (target as any).foto_updated_at = new Date();
}

function applyContratoRules(target: Record<string, any>) {
  const hasAny = target.contrato_prestacion != null || target.contrato_prestacion_mime != null;
  if (!hasAny) return;

  const b64Raw = target.contrato_prestacion;
  const mimeRaw = target.contrato_prestacion_mime;

  const wantsClear =
    (b64Raw === null || b64Raw === undefined || b64Raw === "") &&
    (mimeRaw === null || mimeRaw === undefined || mimeRaw === "");

  if (wantsClear) {
    target.contrato_prestacion = null;
    target.contrato_prestacion_mime = null;
    (target as any).contrato_prestacion_updated_at = new Date();
    return;
  }

  const b64 = normalizeB64(cleanBase64Payload(String(b64Raw || "")));
  const mime = String(mimeRaw || "application/pdf")
    .toLowerCase()
    .trim();

  if (!isValidPdfMime(mime))
    throw Object.assign(new Error("contrato_prestacion_mime inválido (application/pdf)"), { statusCode: 400 });
  if (!b64 || !looksLikeBase64(b64))
    throw Object.assign(new Error("contrato_prestacion inválido (base64)"), { statusCode: 400 });

  const bytes = approxBytesFromBase64(b64);
  const MAX_PDF_BYTES = 3 * 1024 * 1024;
  if (bytes > MAX_PDF_BYTES)
    throw Object.assign(new Error(`Contrato excede el máximo (${MAX_PDF_BYTES} bytes)`), { statusCode: 413 });

  target.contrato_prestacion = b64;
  target.contrato_prestacion_mime = "application/pdf";
  (target as any).contrato_prestacion_updated_at = new Date();
}

async function ensureAuthIfRutApoderadoPresent(rut_apoderado: any, nombre_apoderado?: any): Promise<string | null> {
  if (rut_apoderado === null || rut_apoderado === undefined || rut_apoderado === "") {
    return null;
  }

  const ensured = await ensureApoderadoAuth({
    rut_apoderado: String(rut_apoderado),
    nombre_apoderado:
      nombre_apoderado === null || nombre_apoderado === undefined ? undefined : String(nombre_apoderado),
  });

  if (!ensured.ok) {
    throw Object.assign(new Error(ensured.message || "RUT_APODERADO_INVALID"), {
      statusCode: 400,
      field:
        ensured.message === "NOMBRE_APODERADO_REQUIRED" || ensured.message === "NOMBRE_APODERADO_TOO_LONG"
          ? "nombre_apoderado"
          : "rut_apoderado",
    });
  }

  return ensured.nombre_apoderado;
}

/**
 * Normaliza la selección de sucursales.
 * - Acepta el nuevo arreglo `sucursales`.
 * - Mantiene compatibilidad con `sucursal_id`.
 * - Elimina duplicados.
 */
function normalizeSucursalIds(parsed: any): number[] {
  const raw: any[] =
    Array.isArray(parsed?.sucursales) && parsed.sucursales.length > 0
      ? parsed.sucursales
      : parsed?.sucursal_id !== null && parsed?.sucursal_id !== undefined
        ? [parsed.sucursal_id]
        : [];

  const ids: number[] = raw
    .map((v: any): number => Number(v))
    .filter((v: number): v is number => Number.isFinite(v) && Number.isInteger(v) && v > 0);

  return Array.from(new Set<number>(ids));
}

/**
 * Valida que todas las sucursales:
 * - existan;
 * - pertenezcan a la academia efectiva (tenant).
 */
async function validateSucursalIdsForAcademia(conn: any, academiaId: number, sucursalIds: number[]) {
  if (!Array.isArray(sucursalIds) || sucursalIds.length === 0) {
    throw Object.assign(new Error("Debes seleccionar al menos una sucursal"), {
      statusCode: 400,
      field: "sucursales",
    });
  }

  const placeholders = sucursalIds.map(() => "?").join(",");

  const [rows]: any = await conn.query(
    `SELECT id, academia_id
     FROM sucursales_real
     WHERE id IN (${placeholders})`,
    sucursalIds
  );

  if (!Array.isArray(rows) || rows.length !== sucursalIds.length) {
    throw Object.assign(new Error("Una o más sucursales seleccionadas no existen"), {
      statusCode: 409,
      field: "sucursales",
    });
  }

  const fueraTenant = rows.some((r: any) => Number(r?.academia_id ?? 0) !== Number(academiaId));

  if (fueraTenant) {
    throw Object.assign(new Error("Acceso denegado: una o más sucursales no pertenecen a tu academia"), {
      statusCode: 403,
      field: "sucursales",
    });
  }
}

async function validateForeignKeys(conn: any, data: Record<string, any>) {
  const fkChecks: Array<{ field: string; sql: string; val: any }> = [
    { field: "posicion_id", sql: "SELECT id, academia_id FROM posiciones WHERE id = ? LIMIT 1", val: data.posicion_id },
    {
      field: "categoria_id",
      sql: "SELECT id, academia_id FROM categorias WHERE id = ? LIMIT 1",
      val: data.categoria_id,
    },
    { field: "estado_id", sql: "SELECT id FROM estado WHERE id = ? LIMIT 1", val: data.estado_id },
    { field: "establec_educ_id", sql: "SELECT id FROM establec_educ WHERE id = ? LIMIT 1", val: data.establec_educ_id },
    {
      field: "prevision_medica_id",
      sql: "SELECT id FROM prevision_medica WHERE id = ? LIMIT 1",
      val: data.prevision_medica_id,
    },
    {
      field: "sucursal_id",
      sql: "SELECT id, academia_id FROM sucursales_real WHERE id = ? LIMIT 1",
      val: data.sucursal_id,
    },
    { field: "comuna_id", sql: "SELECT id FROM comunas WHERE id = ? LIMIT 1", val: data.comuna_id },
  ];

  for (const fk of fkChecks) {
    if (fk.val != null) {
      const [r]: any = await conn.query(fk.sql, [fk.val]);
      if (!Array.isArray(r) || r.length === 0) {
        throw Object.assign(new Error(`Violación de clave foránea: ${fk.field} no existe`), {
          statusCode: 409,
          field: fk.field,
        });
      }
    }
  }
}

async function assertBelongsToAcademia(conn: any, academiaId: number, data: Record<string, any>) {
  const checks: Array<{ field: string; table: string; id: any }> = [
    { field: "posicion_id", table: "posiciones", id: data.posicion_id },
    { field: "categoria_id", table: "categorias", id: data.categoria_id },
    { field: "sucursal_id", table: "sucursales_real", id: data.sucursal_id },
  ];

  for (const c of checks) {
    if (c.id == null) continue;

    const [rows]: any = await conn.query(`SELECT academia_id FROM ${c.table} WHERE id = ? LIMIT 1`, [c.id]);
    if (!rows?.length) {
      throw Object.assign(new Error(`Violación de clave foránea: ${c.field} no existe`), {
        statusCode: 409,
        field: c.field,
      });
    }

    const owner = Number(rows[0]?.academia_id ?? 0);
    if (!owner || owner !== academiaId) {
      throw Object.assign(new Error(`Acceso denegado: ${c.field} no pertenece a tu academia`), {
        statusCode: 403,
        field: c.field,
      });
    }
  }
}

export default async function jugadores(app: FastifyInstance) {
  // ✅ Permisos normalizados
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  app.get("/health", { preHandler: canRead }, async (_req, reply) => {
    reply.header("Cache-Control", "no-store");
    return { module: "jugadores", status: "ready", timestamp: new Date().toISOString() };
  });

  // ───────── Listar (read 1/2/3) ─────────
  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const qp = PageQuery.safeParse(req.query);
    if (!qp.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "Query inválida", errors: qp.error.flatten() });
    }
    const { limit, offset, q, include_inactivos } = qp.data;

    try {
      const academiaId = getEffectiveAcademiaId(req);

      let sql =
        "SELECT id, academia_id, deporte_id, rut_jugador, nombre_jugador, edad, email, telefono, peso, estatura, " +
        "talla_polera, talla_short, nombre_apoderado, rut_apoderado, telefono_apoderado, " +
        "posicion_id, categoria_id, establec_educ_id, prevision_medica_id, estado_id, " +
        "direccion, comuna_id, observaciones, fecha_nacimiento, estadistica_id, sucursal_id, " +
        "foto_mime, foto_updated_at, contrato_prestacion_mime, contrato_prestacion_updated_at " +
        "FROM jugadores";

      const args: any[] = [];
      const where: string[] = ["academia_id = ?"];
      args.push(academiaId);

      if (Number(include_inactivos) !== 1) where.push("estado_id = 1");

      if (q) {
        const isNumeric = /^\d+$/.test(q);
        if (isNumeric) {
          where.push("(rut_jugador = ? OR nombre_jugador LIKE ? OR email LIKE ?)");
          args.push(Number(q), `%${q}%`, `%${q}%`);
        } else {
          where.push("(nombre_jugador LIKE ? OR email LIKE ?)");
          args.push(`%${q}%`, `%${q}%`);
        }
      }

      sql += " WHERE " + where.join(" AND ");
      sql += " ORDER BY nombre_jugador ASC, id ASC LIMIT ? OFFSET ?";
      args.push(limit, offset);

      const [rows]: any = await db.query(sql, args);

      reply.header("Cache-Control", "no-store");
      return reply.send({
        ok: true,
        items: (rows || []).map(normalizeListOut),
        limit,
        offset,
        count: rows?.length ?? 0,
        filters: { q: q ?? null, include_inactivos: Number(include_inactivos) === 1 ? 1 : 0 },
      });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al listar jugadores", detail: err?.message });
    }
  });

  // ───────── Listar activos (read 1/2/3) ─────────
  app.get("/activos", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const qp = PageQuery.safeParse(req.query);
    if (!qp.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "Query inválida", errors: qp.error.flatten() });
    }
    const { limit, offset, q } = qp.data;

    try {
      const academiaId = getEffectiveAcademiaId(req);

      let sql =
        "SELECT id, academia_id, deporte_id, rut_jugador, nombre_jugador, edad, email, telefono, peso, estatura, " +
        "talla_polera, talla_short, nombre_apoderado, rut_apoderado, telefono_apoderado, " +
        "posicion_id, categoria_id, establec_educ_id, prevision_medica_id, estado_id, " +
        "direccion, comuna_id, observaciones, fecha_nacimiento, estadistica_id, sucursal_id, " +
        "foto_mime, foto_updated_at, contrato_prestacion_mime, contrato_prestacion_updated_at " +
        "FROM jugadores";

      const args: any[] = [];
      const where: string[] = ["academia_id = ?", "estado_id = 1"];
      args.push(academiaId);

      if (q) {
        const isNumeric = /^\d+$/.test(q);
        if (isNumeric) {
          where.push("(rut_jugador = ? OR nombre_jugador LIKE ? OR email LIKE ?)");
          args.push(Number(q), `%${q}%`, `%${q}%`);
        } else {
          where.push("(nombre_jugador LIKE ? OR email LIKE ?)");
          args.push(`%${q}%`, `%${q}%`);
        }
      }

      sql += " WHERE " + where.join(" AND ");
      sql += " ORDER BY nombre_jugador ASC, id ASC LIMIT ? OFFSET ?";
      args.push(limit, offset);

      const [rows]: any = await db.query(sql, args);

      reply.header("Cache-Control", "no-store");
      return reply.send({
        ok: true,
        items: (rows || []).map(normalizeListOut),
        limit,
        offset,
        count: rows?.length ?? 0,
      });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al listar jugadores activos", detail: err?.message });
    }
  });

  // ───────── GET por RUT (read 1/2/3) ─────────
  app.get("/rut/:rut", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pr = RutParam.safeParse(req.params);
    if (!pr.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: pr.error.issues[0]?.message || "RUT inválido" });
    }

    const rut = pr.data.rut;

    try {
      const academiaId = getEffectiveAcademiaId(req);

      const sql =
        "SELECT id, academia_id, deporte_id, rut_jugador, nombre_jugador, edad, email, telefono, peso, estatura, " +
        "talla_polera, talla_short, nombre_apoderado, rut_apoderado, telefono_apoderado, " +
        "posicion_id, categoria_id, establec_educ_id, prevision_medica_id, estado_id, " +
        "direccion, comuna_id, observaciones, fecha_nacimiento, estadistica_id, sucursal_id, " +
        "foto_base64, foto_mime, foto_updated_at, " +
        "contrato_prestacion, contrato_prestacion_mime, contrato_prestacion_updated_at " +
        "FROM jugadores WHERE academia_id = ? AND rut_jugador = ? LIMIT 1";

      const [rows]: any = await db.query(sql, [academiaId, rut]);

      reply.header("Cache-Control", "no-store");
      if (!rows?.length) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, item: normalizeDetailOut(rows[0]) });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al buscar por RUT", detail: err?.message });
    }
  });

  // ───────── Buscar apoderado por RUT para autocompletar (write 1/3) ─────────
  app.get("/apoderado/rut/:rut", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    reply.header("Cache-Control", "no-store");

    const rawRut = String((req.params as any)?.rut ?? "")
      .replace(/\D/g, "")
      .trim();

    // apoderados_auth trabaja con 8 dígitos sin DV.
    if (!/^\d{8}$/.test(rawRut)) {
      return reply.code(400).send({
        ok: false,
        message: "El RUT del apoderado debe tener 8 dígitos sin DV.",
      });
    }

    try {
      // Tenant efectivo:
      // - superadmin: x-academia-id obligatorio
      // - admin: academia firmada en JWT
      const academiaId = getEffectiveAcademiaId(req);

      /*
       * El apoderado solo puede autocompletarse si ya está relacionado
       * con al menos un jugador perteneciente a la academia efectiva.
       * Esto evita filtrar identidades de apoderados entre tenants.
       */
      const [rows]: any = await db.query(
        `
          SELECT DISTINCT
            aa.apoderado_id,
            aa.rut_apoderado,
            aa.nombre_apoderado
          FROM apoderados_auth aa
          INNER JOIN jugadores j
            ON j.rut_apoderado = aa.rut_apoderado
          WHERE aa.rut_apoderado = ?
            AND j.academia_id = ?
          LIMIT 1
          `,
        [rawRut, academiaId]
      );

      if (!Array.isArray(rows) || rows.length === 0) {
        return reply.code(404).send({
          ok: false,
          exists: false,
          message: "Apoderado no encontrado",
        });
      }

      const nombre = String(rows[0]?.nombre_apoderado ?? "").trim();

      return reply.send({
        ok: true,
        exists: true,
        item: {
          apoderado_id: Number(rows[0]?.apoderado_id ?? 0),
          rut_apoderado: String(rows[0]?.rut_apoderado ?? rawRut),
          nombre_apoderado: nombre || null,
        },
      });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;

      return reply.code(code).send({
        ok: false,
        message: code === 403 ? "Acceso denegado" : "Error al buscar apoderado",
        detail: err?.message,
      });
    }
  });

  // ───────── GET por ID (read 1/2/3) ─────────
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pid = IdParam.safeParse(req.params);
    if (!pid.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    const id = Number(pid.data.id);

    try {
      const academiaId = getEffectiveAcademiaId(req);

      const sql =
        "SELECT id, academia_id, deporte_id, rut_jugador, nombre_jugador, edad, email, telefono, peso, estatura, " +
        "talla_polera, talla_short, nombre_apoderado, rut_apoderado, telefono_apoderado, " +
        "posicion_id, categoria_id, establec_educ_id, prevision_medica_id, estado_id, " +
        "direccion, comuna_id, observaciones, fecha_nacimiento, estadistica_id, sucursal_id, " +
        "foto_base64, foto_mime, foto_updated_at, " +
        "contrato_prestacion, contrato_prestacion_mime, contrato_prestacion_updated_at " +
        "FROM jugadores WHERE academia_id = ? AND id = ? LIMIT 1";

      const [rows]: any = await db.query(sql, [academiaId, id]);

      reply.header("Cache-Control", "no-store");
      if (!rows?.length) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, item: normalizeDetailOut(rows[0]) });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al obtener jugador", detail: err?.message });
    }
  });

  // ───────── Crear (write 1/3) ─────────
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    let conn: any = null;
    let release: () => void = () => {};

    try {
      const parsed = CreateSchema.parse(req.body);

      // Nuevo arreglo N:M, con compatibilidad para sucursal_id antiguo.
      const sucursalIds = normalizeSucursalIds(parsed);

      if (sucursalIds.length === 0) {
        reply.header("Cache-Control", "no-store");
        return reply.code(400).send({
          ok: false,
          field: "sucursales",
          message: "Debes seleccionar al menos una sucursal.",
        });
      }

      // `sucursales` NO es columna de jugadores.
      // La primera sucursal se mantiene en sucursal_id como dato legacy.
      const parsedForJugador: Record<string, any> = {
        ...(parsed as any),
        sucursal_id: sucursalIds[0],
      };
      delete parsedForJugador.sucursales;

      const data = coerceForDB(pickAllowed(parsedForJugador));

      if ("foto_base64" in data || "foto_mime" in data) {
        applyFotoRules(data);
      }

      if ("contrato_prestacion" in data || "contrato_prestacion_mime" in data) {
        applyContratoRules(data);
      }

      // La identidad canónica del apoderado vive en apoderados_auth.
      // Si el RUT ya existe, se reutiliza SIEMPRE su nombre real almacenado.
      const nombreApoderadoCanonico = await ensureAuthIfRutApoderadoPresent(data.rut_apoderado, data.nombre_apoderado);

      if (nombreApoderadoCanonico) {
        data.nombre_apoderado = nombreApoderadoCanonico;
      }

      const got = await getConn();
      conn = got.conn;
      release = got.release;

      const academiaId = getEffectiveAcademiaId(req);
      const ctx = await resolveAcademiaContext(conn, academiaId);

      // Valida las FK tradicionales usando la sucursal principal legacy.
      await validateForeignKeys(conn, data);
      await assertBelongsToAcademia(conn, ctx.academia_id, data);

      // Valida TODAS las sucursales contra el tenant.
      await validateSucursalIdsForAcademia(conn, ctx.academia_id, sucursalIds);

      data.academia_id = ctx.academia_id;
      data.deporte_id = ctx.deporte_id;

      // Unicidad de jugador por tenant.
      if (data.rut_jugador != null) {
        const [r]: any = await conn.query(
          "SELECT id FROM jugadores WHERE academia_id = ? AND rut_jugador = ? LIMIT 1",
          [data.academia_id, data.rut_jugador]
        );

        if (Array.isArray(r) && r.length > 0) {
          reply.header("Cache-Control", "no-store");
          return reply.code(409).send({
            ok: false,
            field: "rut_jugador",
            message: "Duplicado: el RUT ya existe en tu academia",
          });
        }
      }

      if (data.email) {
        const [r2]: any = await conn.query(
          "SELECT id FROM jugadores WHERE academia_id = ? AND LOWER(email)=LOWER(?) LIMIT 1",
          [data.academia_id, data.email]
        );

        if (Array.isArray(r2) && r2.length > 0) {
          reply.header("Cache-Control", "no-store");
          return reply.code(409).send({
            ok: false,
            field: "email",
            message: "Duplicado: el email ya existe en tu academia",
          });
        }
      }

      // Todo el alta queda en una sola transacción:
      // jugador + jugador_sucursal + estadística.
      await conn.beginTransaction();

      const [resJug]: any = await conn.query("INSERT INTO jugadores SET ?", [data]);

      const jugadorId: number = Number(resJug.insertId);

      if (!Number.isFinite(jugadorId) || jugadorId <= 0) {
        throw new Error("No se pudo obtener el ID del jugador creado");
      }

      // Inserta todas las relaciones jugador <-> sucursal.
      const relaciones = sucursalIds.map((sucursalId) => [jugadorId, sucursalId]);

      await conn.query(
        `INSERT INTO jugador_sucursal (jugador_id, sucursal_id)
         VALUES ?`,
        [relaciones]
      );

      // estadistica_id = jugadorId
      await conn.query("UPDATE jugadores SET estadistica_id = ? WHERE id = ? AND academia_id = ?", [
        jugadorId,
        jugadorId,
        data.academia_id,
      ]);

      // Crea estadística si no existe.
      try {
        await conn.query("INSERT INTO estadisticas (estadistica_id) VALUES (?)", [jugadorId]);
      } catch (e: any) {
        if (e?.errno !== 1062 && e?.code !== "ER_DUP_ENTRY") {
          throw e;
        }
      }

      await conn.commit();

      reply.header("Cache-Control", "no-store");

      return reply.code(201).send({
        ok: true,
        id: jugadorId,

        // Respuesta explícita de las sucursales asociadas.
        sucursales: sucursalIds,

        item: {
          ...normalizeDetailOut({
            id: jugadorId,
            ...data,
            estadistica_id: jugadorId,
          }),
          sucursales: sucursalIds,
        },
      });
    } catch (err: any) {
      if (conn) {
        try {
          await conn.rollback();
        } catch {}
      }

      reply.header("Cache-Control", "no-store");

      if (err?.statusCode && typeof err?.message === "string") {
        return reply.code(err.statusCode).send({
          ok: false,
          field: err?.field,
          message: err.message,
        });
      }

      if (err instanceof ZodError) {
        const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");

        return reply.code(400).send({
          ok: false,
          message: "Payload inválido",
          detail,
        });
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        const msg = String(err?.sqlMessage || "").toLowerCase();

        const field = msg.includes("rut_jugador")
          ? "rut_jugador"
          : msg.includes("email")
            ? "email"
            : msg.includes("jugador_sucursal")
              ? "sucursales"
              : undefined;

        return reply.code(409).send({
          ok: false,
          message: field ? `Duplicado: ${field} ya existe` : "Duplicado: clave única violada",
          field,
          detail: err?.sqlMessage,
        });
      }

      if (err?.errno === 1452) {
        return reply.code(409).send({
          ok: false,
          message: "Violación de clave foránea (revisa ids enviados)",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      if (err?.errno === 1054) {
        return reply.code(500).send({
          ok: false,
          message: "Columna desconocida: revisa el esquema de tablas",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      if (err?.errno === 1146 || err?.code === "ER_NO_SUCH_TABLE") {
        return reply.code(500).send({
          ok: false,
          message: "Falta una tabla requerida por el nuevo modelo",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al crear jugador",
        detail: err?.sqlMessage ?? err?.message,
      });
    } finally {
      try {
        release();
      } catch {}
    }
  });

  // ───────── PATCH /jugadores/:id (write 1/3) ─────────
  app.patch("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pid = IdParam.safeParse(req.params);
    if (!pid.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    const id = Number(pid.data.id);

    let conn: any = null;
    let release: () => void = () => {};

    try {
      const academiaId = getEffectiveAcademiaId(req);

      const parsed = UpdateSchema.parse(req.body);
      const changes = coerceForDB(pickAllowed(parsed));
      delete (changes as any).estadistica_id;
      delete (changes as any).academia_id;
      delete (changes as any).deporte_id;

      if ("sucursal_id" in changes && (changes.sucursal_id === null || changes.sucursal_id === undefined)) {
        reply.header("Cache-Control", "no-store");
        return reply
          .code(400)
          .send({ ok: false, field: "sucursal_id", message: "No puedes dejar sucursal en blanco." });
      }

      if ("foto_base64" in changes || "foto_mime" in changes) applyFotoRules(changes);
      if ("contrato_prestacion" in changes || "contrato_prestacion_mime" in changes) applyContratoRules(changes);

      if ("rut_apoderado" in changes || "nombre_apoderado" in changes) {
        let rutEfectivo = changes.rut_apoderado;

        if (rutEfectivo === null || rutEfectivo === undefined || rutEfectivo === "") {
          const [actualRows]: any = await db.query(
            "SELECT rut_apoderado FROM jugadores WHERE id = ? AND academia_id = ? LIMIT 1",
            [id, academiaId]
          );

          rutEfectivo = actualRows?.[0]?.rut_apoderado;
        }

        const nombreCanonico = await ensureAuthIfRutApoderadoPresent(rutEfectivo, changes.nombre_apoderado);

        if (nombreCanonico) {
          changes.nombre_apoderado = nombreCanonico;
        }
      }

      if (Object.keys(changes).length === 0) {
        reply.header("Cache-Control", "no-store");
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const got = await getConn();
      conn = got.conn;
      release = got.release;

      await validateForeignKeys(conn, changes);
      await assertBelongsToAcademia(conn, academiaId, changes);

      const [result]: any = await conn.query("UPDATE jugadores SET ? WHERE id = ? AND academia_id = ?", [
        changes,
        id,
        academiaId,
      ]);

      reply.header("Cache-Control", "no-store");
      if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, updated: { id, ...changes } });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      if (err?.statusCode && typeof err?.message === "string") {
        return reply.code(err.statusCode).send({ ok: false, field: err?.field, message: err.message });
      }

      if (err instanceof ZodError) {
        const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "Duplicado: el RUT (o email) ya existe" });
      }

      if (err?.errno === 1452) {
        return reply.code(409).send({
          ok: false,
          message: "Violación de clave foránea (revisa ids enviados)",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(500).send({ ok: false, message: "Error al actualizar jugador", detail: err?.message });
    } finally {
      try {
        release();
      } catch {}
    }
  });

  // ───────── PATCH /jugadores/rut/:rut (write 1/3) ─────────
  app.patch("/rut/:rut", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pr = RutParam.safeParse(req.params);
    if (!pr.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: pr.error.issues[0]?.message || "RUT inválido" });
    }

    const rut = pr.data.rut;

    let conn: any = null;
    let release: () => void = () => {};

    try {
      const academiaId = getEffectiveAcademiaId(req);

      const parsed = UpdateSchema.parse(req.body);
      const changes = coerceForDB(pickAllowed(parsed));
      delete (changes as any).estadistica_id;
      delete (changes as any).academia_id;
      delete (changes as any).deporte_id;

      if ("sucursal_id" in changes && (changes.sucursal_id === null || changes.sucursal_id === undefined)) {
        reply.header("Cache-Control", "no-store");
        return reply
          .code(400)
          .send({ ok: false, field: "sucursal_id", message: "No puedes dejar sucursal en blanco." });
      }

      if ("foto_base64" in changes || "foto_mime" in changes) applyFotoRules(changes);
      if ("contrato_prestacion" in changes || "contrato_prestacion_mime" in changes) applyContratoRules(changes);

      if ("rut_apoderado" in changes || "nombre_apoderado" in changes) {
        let rutEfectivo = changes.rut_apoderado;

        if (rutEfectivo === null || rutEfectivo === undefined || rutEfectivo === "") {
          const [actualRows]: any = await db.query(
            "SELECT rut_apoderado FROM jugadores WHERE rut_jugador = ? AND academia_id = ? LIMIT 1",
            [rut, academiaId]
          );

          rutEfectivo = actualRows?.[0]?.rut_apoderado;
        }

        const nombreCanonico = await ensureAuthIfRutApoderadoPresent(rutEfectivo, changes.nombre_apoderado);

        if (nombreCanonico) {
          changes.nombre_apoderado = nombreCanonico;
        }
      }

      if (Object.keys(changes).length === 0) {
        reply.header("Cache-Control", "no-store");
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const got = await getConn();
      conn = got.conn;
      release = got.release;

      await validateForeignKeys(conn, changes);
      await assertBelongsToAcademia(conn, academiaId, changes);

      const [result]: any = await conn.query("UPDATE jugadores SET ? WHERE rut_jugador = ? AND academia_id = ?", [
        changes,
        rut,
        academiaId,
      ]);

      reply.header("Cache-Control", "no-store");
      if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, updated: { rut_jugador: rut, ...changes } });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      if (err?.statusCode && typeof err?.message === "string") {
        return reply.code(err.statusCode).send({ ok: false, field: err?.field, message: err.message });
      }

      if (err instanceof ZodError) {
        const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "Duplicado: el RUT (o email) ya existe" });
      }

      if (err?.errno === 1452) {
        return reply.code(409).send({
          ok: false,
          message: "Violación de clave foránea (revisa ids enviados)",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(500).send({ ok: false, message: "Error al actualizar jugador por RUT", detail: err?.message });
    } finally {
      try {
        release();
      } catch {}
    }
  });

  // ───────── DELETE (write 1/3) ─────────
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pid = IdParam.safeParse(req.params);
    if (!pid.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    const id = Number(pid.data.id);

    try {
      const academiaId = getEffectiveAcademiaId(req);

      const [result]: any = await db.query("DELETE FROM jugadores WHERE id = ? AND academia_id = ?", [id, academiaId]);

      reply.header("Cache-Control", "no-store");
      if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      if (err?.errno === 1451 || err?.code === "ER_ROW_IS_REFERENCED_2") {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: hay referencias asociadas.",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      if (err?.statusCode && Number.isFinite(err.statusCode)) {
        return reply.code(err.statusCode).send({
          ok: false,
          message: err?.message ?? "Acceso denegado",
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar jugador",
        detail: err?.message,
      });
    }
  });
}
