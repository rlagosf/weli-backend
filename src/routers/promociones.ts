// src/routers/promociones.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * Tabla: promociones_academia
 *
 * Campos:
 * - id
 * - academia_id
 * - nombre
 * - descripcion
 * - tipo_beneficio
 * - valor
 * - fecha_desde
 * - fecha_hasta
 * - estado_id
 * - created_at
 * - updated_at
 *
 * Scope:
 * - Multi-academia
 *
 * Seguridad:
 * - READ: roles 1,2,3
 * - WRITE: roles 1,3
 *
 * academia_id:
 * - Admin/Staff: JWT firmado
 * - Superadmin: x-academia-id validado
 *
 * Reglas:
 * - academia_id nunca se acepta desde body.
 * - tipo_beneficio:
 *      PORCENTAJE
 *      DESCUENTO_FIJO
 *      PRECIO_FIJO
 * - PORCENTAJE: 0 <= valor <= 100.
 * - montos: 0 <= valor <= 99.999.999,99.
 * - fecha_hasta >= fecha_desde.
 * - una promoción utilizada en cargos conserva
 *   tipo_beneficio, valor y fecha_desde.
 * - fecha_hasta no puede invalidar cargos históricos.
 */

/* =========================================================
   Schemas
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const DateString = z
  .string()
  .trim()
  .regex(/^\d{4}-\d{2}-\d{2}$/, "Fecha inválida. Formato esperado: YYYY-MM-DD");

const TipoBeneficio = z.enum(["PORCENTAJE", "DESCUENTO_FIJO", "PRECIO_FIJO"]);

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(120),
    descripcion: z.string().trim().max(500).nullable().optional().default(null),

    tipo_beneficio: TipoBeneficio,
    valor: z.coerce.number().finite().min(0),

    fecha_desde: DateString,
    fecha_hasta: z.union([DateString, z.null()]).optional().default(null),

    estado_id: z.coerce.number().int().positive().max(255).default(1),
  })
  .strict();

const PutSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(120),
    descripcion: z.string().trim().max(500).nullable(),

    tipo_beneficio: TipoBeneficio,
    valor: z.coerce.number().finite().min(0),

    fecha_desde: DateString,
    fecha_hasta: z.union([DateString, z.null()]),

    estado_id: z.coerce.number().int().positive().max(255),
  })
  .strict();

const PatchSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(120).optional(),
    descripcion: z.string().trim().max(500).nullable().optional(),

    tipo_beneficio: TipoBeneficio.optional(),
    valor: z.coerce.number().finite().min(0).optional(),

    fecha_desde: DateString.optional(),
    fecha_hasta: z.union([DateString, z.null()]).optional(),

    estado_id: z.coerce.number().int().positive().max(255).optional(),
  })
  .strict();

const QuerySchema = z
  .object({
    estado_id: z.coerce.number().int().positive().max(255).optional(),
    tipo_beneficio: TipoBeneficio.optional(),

    vigentes: z.enum(["1", "0"]).optional(),
    fecha: DateString.optional(),

    limit: z.coerce.number().int().min(1).max(500).default(200),
  })
  .strict();

/* =========================================================
   Helpers
========================================================= */

function zodDetail(err: ZodError) {
  return err.issues.map((i) => `${i.path.join(".") || "field"}: ${i.message}`).join("; ");
}

function resolveAcademiaId(req: FastifyRequest) {
  const academiaId = Number(getEffectiveAcademiaId(req));

  if (!Number.isInteger(academiaId) || academiaId <= 0) {
    const err: any = new Error("Academia efectiva inválida");
    err.statusCode = 403;
    throw err;
  }

  return academiaId;
}

function normalizeDescripcion(value: string | null | undefined) {
  if (value == null) return null;
  const text = String(value).trim();
  return text || null;
}

function dbDate(value: any): string | null {
  if (value == null) return null;
  if (value instanceof Date) return value.toISOString().slice(0, 10);
  return String(value).slice(0, 10);
}

function normalize(row: any) {
  return {
    id: Number(row.id),
    academia_id: Number(row.academia_id),

    nombre: String(row.nombre ?? ""),
    descripcion: row.descripcion == null ? null : String(row.descripcion),

    tipo_beneficio: String(row.tipo_beneficio ?? ""),
    valor: Number(row.valor ?? 0),

    fecha_desde: row.fecha_desde ?? null,
    fecha_hasta: row.fecha_hasta ?? null,

    estado_id: Number(row.estado_id),

    created_at: row.created_at ?? null,
    updated_at: row.updated_at ?? null,
  };
}

function validateDates(fechaDesde: string, fechaHasta: string | null) {
  const desde = new Date(`${fechaDesde}T00:00:00Z`);

  if (Number.isNaN(desde.getTime())) {
    throw new Error("fecha_desde inválida");
  }

  if (fechaHasta !== null) {
    const hasta = new Date(`${fechaHasta}T00:00:00Z`);

    if (Number.isNaN(hasta.getTime())) {
      throw new Error("fecha_hasta inválida");
    }

    if (hasta < desde) {
      throw new Error("fecha_hasta no puede ser anterior a fecha_desde");
    }
  }
}

function validateBenefit(tipoBeneficio: string, rawValor: number) {
  const valor = Number(rawValor);

  if (!Number.isFinite(valor) || valor < 0) {
    throw new Error("Valor de promoción inválido");
  }

  if (tipoBeneficio === "PORCENTAJE") {
    if (valor > 100) {
      throw new Error("El porcentaje de descuento no puede superar 100");
    }

    return Number(valor.toFixed(2));
  }

  if (tipoBeneficio === "DESCUENTO_FIJO" || tipoBeneficio === "PRECIO_FIJO") {
    if (valor > 99999999.99) {
      throw new Error("El valor de la promoción supera el máximo permitido");
    }

    return Number(valor.toFixed(2));
  }

  throw new Error("Tipo de beneficio inválido");
}

async function getPromocion(academiaId: number, id: number) {
  const [rows]: any = await db.query(
    `
    SELECT
      id,
      academia_id,
      nombre,
      descripcion,
      tipo_beneficio,
      valor,
      fecha_desde,
      fecha_hasta,
      estado_id,
      created_at,
      updated_at
    FROM promociones_academia
    WHERE id = ?
      AND academia_id = ?
    LIMIT 1
    `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

async function existsByNombre(academiaId: number, nombre: string, excludeId?: number) {
  const values: any[] = [academiaId, String(nombre).trim()];

  let sql = `
    SELECT id
    FROM promociones_academia
    WHERE academia_id = ?
      AND LOWER(TRIM(nombre)) = LOWER(?)
  `;

  if (excludeId) {
    sql += ` AND id <> ?`;
    values.push(excludeId);
  }

  sql += ` LIMIT 1`;

  const [rows]: any = await db.query(sql, values);
  return Array.isArray(rows) && rows.length > 0;
}

/**
 * Devuelve información sobre el uso histórico
 * de una promoción en cargos.
 */
async function getUsageSummary(academiaId: number, promocionId: number) {
  const [rows]: any = await db.query(
    `
    SELECT
      COUNT(*) AS total,
      MIN(periodo_desde) AS primer_periodo,
      MAX(periodo_desde) AS ultimo_periodo
    FROM cargos_jugador
    WHERE academia_id = ?
      AND promocion_id = ?
    `,
    [academiaId, promocionId]
  );

  const row = rows?.[0] ?? {};

  return {
    total: Number(row.total ?? 0),
    primer_periodo: dbDate(row.primer_periodo),
    ultimo_periodo: dbDate(row.ultimo_periodo),
  };
}

async function hasRelations(academiaId: number, promocionId: number) {
  const [planRows]: any = await db.query(
    `SELECT id FROM promocion_plan WHERE academia_id = ? AND promocion_id = ? LIMIT 1`,
    [academiaId, promocionId]
  );

  if (planRows?.length) return true;

  const [sucursalRows]: any = await db.query(
    `SELECT id FROM promocion_sucursal WHERE academia_id = ? AND promocion_id = ? LIMIT 1`,
    [academiaId, promocionId]
  );

  if (sucursalRows?.length) return true;

  const [tipoRows]: any = await db.query(
    `SELECT id FROM promocion_tipo_pago WHERE academia_id = ? AND promocion_id = ? LIMIT 1`,
    [academiaId, promocionId]
  );

  return Array.isArray(tipoRows) && tipoRows.length > 0;
}

function validateHistoricalMutation(
  current: any,
  next: {
    tipo_beneficio: string;
    valor: number;
    fecha_desde: string;
    fecha_hasta: string | null;
  },
  usage: {
    total: number;
    primer_periodo: string | null;
    ultimo_periodo: string | null;
  }
) {
  if (usage.total <= 0) return;

  const currentTipo = String(current.tipo_beneficio ?? "");
  const currentValor = Number(current.valor ?? 0);
  const currentDesde = dbDate(current.fecha_desde);

  if (next.tipo_beneficio !== currentTipo || next.valor !== currentValor || next.fecha_desde !== currentDesde) {
    throw new Error(
      "La promoción posee cargos asociados. No se puede modificar tipo de beneficio, valor ni fecha inicial"
    );
  }

  /*
   * Si ya existen cargos, fecha_hasta no puede
   * quedar antes del último período histórico
   * donde la promoción fue utilizada.
   */
  if (next.fecha_hasta !== null && usage.ultimo_periodo !== null && next.fecha_hasta < usage.ultimo_periodo) {
    throw new Error(`La promoción fue utilizada hasta ${usage.ultimo_periodo}; fecha_hasta no puede ser anterior`);
  }
}

function handleScopeError(reply: FastifyReply, err: any) {
  const status = Number(err?.statusCode ?? 0);

  if ([400, 401, 403].includes(status)) {
    reply.header("Cache-Control", "no-store");

    return reply.code(status).send({
      ok: false,
      message: err?.message ?? "No fue posible determinar la academia efectiva",
    });
  }

  return null;
}

function isBusinessValidationError(err: any) {
  const message = String(err?.message ?? "");

  return (
    [
      "fecha_desde inválida",
      "fecha_hasta inválida",
      "fecha_hasta no puede ser anterior a fecha_desde",
      "Valor de promoción inválido",
      "El porcentaje de descuento no puede superar 100",
      "El valor de la promoción supera el máximo permitido",
      "Tipo de beneficio inválido",
      "La promoción posee cargos asociados. No se puede modificar tipo de beneficio, valor ni fecha inicial",
    ].includes(message) || message.startsWith("La promoción fue utilizada hasta")
  );
}

/* =========================================================
   Router
========================================================= */

export default async function promociones(app: FastifyInstance) {
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  /* =======================================================
     HEALTH
  ======================================================= */

  app.get("/health", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academiaId = resolveAcademiaId(req);

      reply.header("Cache-Control", "no-store");

      return reply.send({
        module: "promociones_academia",
        status: "ready",
        academia_id: academiaId,
        timestamp: new Date().toISOString(),
      });
    } catch (err: any) {
      const handled = handleScopeError(reply, err);
      if (handled) return handled;

      reply.header("Cache-Control", "no-store");
      return reply.code(500).send({ ok: false, message: "Error en módulo promociones" });
    }
  });

  /* =======================================================
     GET /
  ======================================================= */

  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academiaId = resolveAcademiaId(req);
      const query = QuerySchema.parse(req.query);

      const where: string[] = ["academia_id = ?"];
      const values: any[] = [academiaId];

      if (query.estado_id !== undefined) {
        where.push("estado_id = ?");
        values.push(query.estado_id);
      }

      if (query.tipo_beneficio !== undefined) {
        where.push("tipo_beneficio = ?");
        values.push(query.tipo_beneficio);
      }

      const fechaReferencia = query.fecha ?? null;

      if (query.vigentes === "1") {
        if (fechaReferencia) {
          where.push("fecha_desde <= ?");
          where.push("(fecha_hasta IS NULL OR fecha_hasta >= ?)");
          values.push(fechaReferencia, fechaReferencia);
        } else {
          where.push("fecha_desde <= CURDATE()");
          where.push("(fecha_hasta IS NULL OR fecha_hasta >= CURDATE())");
        }
      }

      if (query.vigentes === "0") {
        if (fechaReferencia) {
          where.push("(fecha_desde > ? OR (fecha_hasta IS NOT NULL AND fecha_hasta < ?))");
          values.push(fechaReferencia, fechaReferencia);
        } else {
          where.push("(fecha_desde > CURDATE() OR (fecha_hasta IS NOT NULL AND fecha_hasta < CURDATE()))");
        }
      }

      values.push(query.limit);

      const [rows]: any = await db.query(
        `
        SELECT
          id,
          academia_id,
          nombre,
          descripcion,
          tipo_beneficio,
          valor,
          fecha_desde,
          fecha_hasta,
          estado_id,
          created_at,
          updated_at
        FROM promociones_academia
        WHERE ${where.join(" AND ")}
        ORDER BY fecha_desde DESC, nombre ASC, id DESC
        LIMIT ?
        `,
        values
      );

      reply.header("Cache-Control", "no-store");

      return reply.send({
        ok: true,
        count: rows?.length ?? 0,
        items: (rows ?? []).map(normalize),
      });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      if (err instanceof ZodError) {
        return reply.code(400).send({
          ok: false,
          message: "Parámetros inválidos",
          detail: zodDetail(err),
        });
      }

      const handled = handleScopeError(reply, err);
      if (handled) return handled;

      return reply.code(500).send({
        ok: false,
        message: "Error al listar promociones",
      });
    }
  });

  /* =======================================================
     GET /:id
  ======================================================= */

  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);

    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const academiaId = resolveAcademiaId(req);
      const row = await getPromocion(academiaId, parsed.data.id);

      reply.header("Cache-Control", "no-store");

      if (!row) {
        return reply.code(404).send({
          ok: false,
          message: "Promoción no encontrada",
        });
      }

      return reply.send({
        ok: true,
        item: normalize(row),
      });
    } catch (err: any) {
      const handled = handleScopeError(reply, err);
      if (handled) return handled;

      reply.header("Cache-Control", "no-store");

      return reply.code(500).send({
        ok: false,
        message: "Error al obtener promoción",
      });
    }
  });

  /* =======================================================
     POST /
  ======================================================= */

  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academiaId = resolveAcademiaId(req);
      const body = CreateSchema.parse(req.body);

      validateDates(body.fecha_desde, body.fecha_hasta);

      const valor = validateBenefit(body.tipo_beneficio, body.valor);
      const nombre = body.nombre.trim();
      const descripcion = normalizeDescripcion(body.descripcion);

      if (await existsByNombre(academiaId, nombre)) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "Ya existe una promoción con ese nombre en esta academia",
        });
      }

      const [result]: any = await db.query(
        `
        INSERT INTO promociones_academia
          (
            academia_id,
            nombre,
            descripcion,
            tipo_beneficio,
            valor,
            fecha_desde,
            fecha_hasta,
            estado_id
          )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          academiaId,
          nombre,
          descripcion,
          body.tipo_beneficio,
          valor,
          body.fecha_desde,
          body.fecha_hasta,
          body.estado_id,
        ]
      );

      const insertId = Number(result?.insertId);
      const row = await getPromocion(academiaId, insertId);

      reply.header("Cache-Control", "no-store");

      return reply.code(201).send({
        ok: true,
        id: insertId,

        item: row
          ? normalize(row)
          : {
              id: insertId,
              academia_id: academiaId,
              nombre,
              descripcion,
              tipo_beneficio: body.tipo_beneficio,
              valor,
              fecha_desde: body.fecha_desde,
              fecha_hasta: body.fecha_hasta,
              estado_id: body.estado_id,
            },
      });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      if (err instanceof ZodError) {
        return reply.code(400).send({
          ok: false,
          message: "Payload inválido",
          detail: zodDetail(err),
        });
      }

      const handled = handleScopeError(reply, err);
      if (handled) return handled;

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({
          ok: false,
          message: "Ya existe una promoción con esos datos",
        });
      }

      if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
        return reply.code(409).send({
          ok: false,
          message: "Uno o más datos relacionados no existen",
        });
      }

      if (isBusinessValidationError(err)) {
        return reply.code(400).send({
          ok: false,
          message: err.message,
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al crear promoción",
      });
    }
  });

  /* =======================================================
     PUT /:id
  ======================================================= */

  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);

    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const academiaId = resolveAcademiaId(req);
      const id = parsed.data.id;

      const current = await getPromocion(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");
        return reply.code(404).send({ ok: false, message: "Promoción no encontrada" });
      }

      const body = PutSchema.parse(req.body);

      validateDates(body.fecha_desde, body.fecha_hasta);

      const valor = validateBenefit(body.tipo_beneficio, body.valor);
      const nombre = body.nombre.trim();
      const descripcion = normalizeDescripcion(body.descripcion);

      if (await existsByNombre(academiaId, nombre, id)) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "Ya existe otra promoción con ese nombre en esta academia",
        });
      }

      const usage = await getUsageSummary(academiaId, id);

      validateHistoricalMutation(
        current,
        {
          tipo_beneficio: body.tipo_beneficio,
          valor,
          fecha_desde: body.fecha_desde,
          fecha_hasta: body.fecha_hasta,
        },
        usage
      );

      const [result]: any = await db.query(
        `
        UPDATE promociones_academia
        SET
          nombre = ?,
          descripcion = ?,
          tipo_beneficio = ?,
          valor = ?,
          fecha_desde = ?,
          fecha_hasta = ?,
          estado_id = ?
        WHERE id = ?
          AND academia_id = ?
        LIMIT 1
        `,
        [
          nombre,
          descripcion,
          body.tipo_beneficio,
          valor,
          body.fecha_desde,
          body.fecha_hasta,
          body.estado_id,
          id,
          academiaId,
        ]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Promoción no encontrada",
        });
      }

      const updated = await getPromocion(academiaId, id);

      return reply.send({
        ok: true,
        updated: updated ? normalize(updated) : { id, academia_id: academiaId },
      });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      if (err instanceof ZodError) {
        return reply.code(400).send({
          ok: false,
          message: "Payload inválido",
          detail: zodDetail(err),
        });
      }

      const handled = handleScopeError(reply, err);
      if (handled) return handled;

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({
          ok: false,
          message: "Ya existe otra promoción con esos datos",
        });
      }

      if (isBusinessValidationError(err)) {
        return reply.code(409).send({
          ok: false,
          message: err.message,
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar promoción",
      });
    }
  });

  /* =======================================================
     PATCH /:id
  ======================================================= */

  app.patch("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);

    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const academiaId = resolveAcademiaId(req);
      const id = parsed.data.id;

      const current = await getPromocion(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Promoción no encontrada",
        });
      }

      const body = PatchSchema.parse(req.body);

      if (Object.keys(body).length === 0) {
        reply.header("Cache-Control", "no-store");

        return reply.code(400).send({
          ok: false,
          message: "No hay campos para actualizar",
        });
      }

      const merged = {
        nombre: body.nombre ?? String(current.nombre),

        descripcion:
          body.descripcion !== undefined
            ? normalizeDescripcion(body.descripcion)
            : normalizeDescripcion(current.descripcion),

        tipo_beneficio: body.tipo_beneficio ?? String(current.tipo_beneficio),

        valor: body.valor !== undefined ? body.valor : Number(current.valor),

        fecha_desde: body.fecha_desde ?? dbDate(current.fecha_desde)!,

        fecha_hasta: body.fecha_hasta !== undefined ? body.fecha_hasta : dbDate(current.fecha_hasta),

        estado_id: body.estado_id ?? Number(current.estado_id),
      };

      validateDates(merged.fecha_desde, merged.fecha_hasta);

      const valor = validateBenefit(merged.tipo_beneficio, merged.valor);

      const nombre = merged.nombre.trim();

      if (await existsByNombre(academiaId, nombre, id)) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "Ya existe otra promoción con ese nombre en esta academia",
        });
      }

      const usage = await getUsageSummary(academiaId, id);

      validateHistoricalMutation(
        current,
        {
          tipo_beneficio: merged.tipo_beneficio,
          valor,
          fecha_desde: merged.fecha_desde,
          fecha_hasta: merged.fecha_hasta,
        },
        usage
      );

      const [result]: any = await db.query(
        `
        UPDATE promociones_academia
        SET
          nombre = ?,
          descripcion = ?,
          tipo_beneficio = ?,
          valor = ?,
          fecha_desde = ?,
          fecha_hasta = ?,
          estado_id = ?
        WHERE id = ?
          AND academia_id = ?
        LIMIT 1
        `,
        [
          nombre,
          merged.descripcion,
          merged.tipo_beneficio,
          valor,
          merged.fecha_desde,
          merged.fecha_hasta,
          merged.estado_id,
          id,
          academiaId,
        ]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Promoción no encontrada",
        });
      }

      const updated = await getPromocion(academiaId, id);

      return reply.send({
        ok: true,
        updated: updated ? normalize(updated) : { id, academia_id: academiaId },
      });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      if (err instanceof ZodError) {
        return reply.code(400).send({
          ok: false,
          message: "Payload inválido",
          detail: zodDetail(err),
        });
      }

      const handled = handleScopeError(reply, err);
      if (handled) return handled;

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({
          ok: false,
          message: "Ya existe otra promoción con esos datos",
        });
      }

      if (isBusinessValidationError(err)) {
        return reply.code(409).send({
          ok: false,
          message: err.message,
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar promoción",
      });
    }
  });

  /* =======================================================
     DELETE /:id
  ======================================================= */

  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);

    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const academiaId = resolveAcademiaId(req);
      const id = parsed.data.id;

      const current = await getPromocion(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Promoción no encontrada",
        });
      }

      const usage = await getUsageSummary(academiaId, id);

      if (usage.total > 0) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La promoción posee cargos asociados y no puede eliminarse. Debe desactivarla o cerrar su vigencia",
        });
      }

      if (await hasRelations(academiaId, id)) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message:
            "La promoción posee asociaciones con planes, sucursales o tipos de pago. Debe eliminar primero esas asociaciones",
        });
      }

      const [result]: any = await db.query(
        `
        DELETE FROM promociones_academia
        WHERE id = ?
          AND academia_id = ?
        LIMIT 1
        `,
        [id, academiaId]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Promoción no encontrada",
        });
      }

      return reply.send({
        ok: true,
        deleted: id,
      });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      const handled = handleScopeError(reply, err);
      if (handled) return handled;

      if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar la promoción porque está en uso",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar promoción",
      });
    }
  });
}
