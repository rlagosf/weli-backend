// src/routers/pagos_jugador.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z } from "zod";

import { db } from "../db";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/* =========================================================
   CONSTANTES
========================================================= */

const ESTADO_ACTIVO = 1;

/* =========================================================
   HELPERS GENERALES
========================================================= */

function resolveAcademiaId(req: FastifyRequest): number {
  const academiaId = Number(getEffectiveAcademiaId(req));

  if (!Number.isInteger(academiaId) || academiaId <= 0) {
    const err: any = new Error("Academia efectiva inválida");

    err.statusCode = 403;

    throw err;
  }

  return academiaId;
}

function businessError(message: string, statusCode = 400): never {
  const err: any = new Error(message);

  err.statusCode = statusCode;

  throw err;
}

function getStatusCode(err: any): number {
  const status = Number(err?.statusCode ?? 0);

  if (Number.isInteger(status) && status >= 400 && status <= 599) {
    return status;
  }

  return 500;
}

function roundMoney(value: number): number {
  return Math.round((Number(value) + Number.EPSILON) * 100) / 100;
}

function toSQLDate(input: string): string | null {
  if (!input) {
    return null;
  }

  if (/^\d{4}-\d{2}-\d{2}$/.test(input)) {
    const parsed = new Date(`${input}T00:00:00Z`);

    if (Number.isNaN(parsed.getTime())) {
      return null;
    }

    return input;
  }

  const parsed = new Date(input);

  if (Number.isNaN(parsed.getTime())) {
    return null;
  }

  return parsed.toISOString().slice(0, 10);
}

function cleanNullableString(value: unknown): string | null {
  if (value === null || value === undefined) {
    return null;
  }

  const text = String(value).trim();

  return text || null;
}

/* =========================================================
   SCHEMAS
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const RutParam = z.object({
  jugador_rut: z.coerce.number().int().positive(),
});

const DetalleSchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive(),

    origen: z.enum(["REGULAR", "ADICIONAL"]).default("REGULAR"),

    observaciones: z.string().trim().max(255).nullable().optional(),
  })
  .strict();

const CreateSchema = z
  .object({
    jugador_id: z.coerce.number().int().positive(),

    sucursal_id: z.union([z.coerce.number().int().positive(), z.null()]).optional().default(null),

    plan_catalogo_id: z.union([z.coerce.number().int().positive(), z.null()]).optional().default(null),

    situacion_pago_id: z.coerce.number().int().positive(),

    fecha_pago: z.string().min(10),

    medio_pago_id: z.coerce.number().int().positive(),

    comprobante_url: z.string().url().nullable().optional(),

    observaciones: z.string().nullable().optional(),

    detalles: z.array(DetalleSchema).min(1, "Debe registrar al menos un concepto de pago").max(50),
  })
  .strict();

const UpdateSchema = z
  .object({
    jugador_id: z.coerce.number().int().positive().optional(),

    sucursal_id: z.union([z.coerce.number().int().positive(), z.null()]).optional(),

    plan_catalogo_id: z.union([z.coerce.number().int().positive(), z.null()]).optional(),

    situacion_pago_id: z.coerce.number().int().positive().optional(),

    fecha_pago: z.string().min(10).optional(),

    medio_pago_id: z.coerce.number().int().positive().optional(),

    comprobante_url: z.string().url().nullable().optional(),

    observaciones: z.string().nullable().optional(),

    detalles: z.array(DetalleSchema).min(1).max(50).optional(),
  })
  .strict();

const PageQuery = z.object({
  limit: z.coerce.number().int().positive().max(1000).default(50),

  offset: z.coerce.number().int().nonnegative().default(0),
});

const ListQuery = PageQuery.extend({
  year: z.coerce.number().int().optional(),

  month: z.coerce.number().int().min(1).max(12).optional(),

  tipo_pago_id: z.coerce.number().int().positive().optional(),

  jugador_rut: z.coerce.number().int().positive().optional(),

  jugador_id: z.coerce.number().int().positive().optional(),

  sucursal_id: z.coerce.number().int().positive().optional(),

  plan_catalogo_id: z.coerce.number().int().positive().optional(),

  situacion_pago_id: z.coerce.number().int().positive().optional(),
});

/* =========================================================
   VALIDACIÓN JUGADOR
========================================================= */

async function getJugadorOrThrow(conn: any, academiaId: number, jugadorId: number) {
  const [rows]: any = await conn.query(
    `
        SELECT
          id,
          rut_jugador,
          nombre_jugador,
          academia_id,
          categoria_id

        FROM jugadores

        WHERE id = ?
          AND academia_id = ?

        LIMIT 1
      `,
    [jugadorId, academiaId]
  );

  if (!rows?.length) {
    businessError("FORBIDDEN_JUGADOR", 403);
  }

  return rows[0];
}

async function getJugadorByRutOrThrow(conn: any, academiaId: number, jugadorRut: number) {
  const [rows]: any = await conn.query(
    `
        SELECT
          id,
          rut_jugador,
          nombre_jugador,
          academia_id

        FROM jugadores

        WHERE rut_jugador = ?
          AND academia_id = ?

        LIMIT 1
      `,
    [jugadorRut, academiaId]
  );

  if (!rows?.length) {
    businessError("FORBIDDEN_JUGADOR", 403);
  }

  return rows[0];
}

/* =========================================================
   VALIDACIÓN SUCURSAL
========================================================= */

async function assertSucursalOrThrow(conn: any, academiaId: number, jugadorId: number, sucursalId: number | null) {
  if (sucursalId === null) {
    return;
  }

  const [sucursalRows]: any = await conn.query(
    `
        SELECT id

        FROM sucursales_real

        WHERE id = ?
          AND academia_id = ?

        LIMIT 1
      `,
    [sucursalId, academiaId]
  );

  if (!sucursalRows?.length) {
    businessError("La sucursal no existe o no pertenece a la academia");
  }

  /*
   * El jugador puede pertenecer a múltiples sucursales.
   * Validamos la tabla puente acordada.
   */
  const [relationRows]: any = await conn.query(
    `
        SELECT id

        FROM jugador_sucursal

        WHERE academia_id = ?
          AND jugador_id = ?
          AND sucursal_id = ?

        LIMIT 1
      `,
    [academiaId, jugadorId, sucursalId]
  );

  if (!relationRows?.length) {
    businessError("El jugador no pertenece a la sucursal seleccionada");
  }
}

/* =========================================================
   CATÁLOGOS GLOBALES
========================================================= */

async function assertSituacionPagoOrThrow(conn: any, situacionPagoId: number) {
  const [rows]: any = await conn.query(
    `
        SELECT id

        FROM situacion_pago

        WHERE id = ?

        LIMIT 1
      `,
    [situacionPagoId]
  );

  if (!rows?.length) {
    businessError("La situación de pago no existe");
  }
}

async function assertMedioPagoOrThrow(conn: any, medioPagoId: number) {
  const [rows]: any = await conn.query(
    `
        SELECT id

        FROM medio_pago

        WHERE id = ?

        LIMIT 1
      `,
    [medioPagoId]
  );

  if (!rows?.length) {
    businessError("El medio de pago no existe");
  }
}

/* =========================================================
   PLAN
========================================================= */

async function assertPlanForPaymentOrThrow(
  conn: any,
  academiaId: number,
  jugadorId: number,
  planId: number | null,
  fechaPago: string
) {
  if (planId === null) {
    return;
  }

  /*
   * 1. Plan global existente/activo.
   * 2. Plan habilitado para academia.
   */
  const [planRows]: any = await conn.query(
    `
        SELECT
          pc.id,
          pc.estado_id
            AS catalogo_estado_id,

          ap.estado_id
            AS academia_plan_estado_id

        FROM planes_catalogo pc

        INNER JOIN academia_plan ap
          ON ap.plan_id = pc.id
         AND ap.academia_id = ?

        WHERE pc.id = ?

        LIMIT 1
      `,
    [academiaId, planId]
  );

  if (!planRows?.length) {
    businessError("El plan no existe o no está habilitado para la academia");
  }

  if (Number(planRows[0].catalogo_estado_id) !== ESTADO_ACTIVO) {
    businessError("El plan no se encuentra activo en el catálogo global");
  }

  if (Number(planRows[0].academia_plan_estado_id) !== ESTADO_ACTIVO) {
    businessError("El plan no se encuentra habilitado para la academia");
  }

  /*
   * El jugador debe tener ese plan asignado
   * y vigente para la fecha del pago.
   */
  const [assignmentRows]: any = await conn.query(
    `
        SELECT id

        FROM jugador_plan_catalogo

        WHERE academia_id = ?
          AND jugador_id = ?
          AND plan_id = ?
          AND estado_id = 1
          AND fecha_inicio <= ?

          AND (
            fecha_fin IS NULL
            OR fecha_fin >= ?
          )

        LIMIT 1
      `,
    [academiaId, jugadorId, planId, fechaPago, fechaPago]
  );

  if (!assignmentRows?.length) {
    businessError("El jugador no posee el plan seleccionado vigente para la fecha del pago");
  }
}

/* =========================================================
   TIPO DE PAGO + TARIFA
========================================================= */

async function getTarifaOrThrow(conn: any, academiaId: number, tipoPagoId: number) {
  const [rows]: any = await conn.query(
    `
        SELECT
          tp.id
            AS tipo_pago_id,

          tp.nombre
            AS tipo_pago_nombre,

          atp.estado_id
            AS academia_tipo_pago_estado,

          ta.id
            AS tarifa_id,

          ta.monto,

          ta.estado_id
            AS tarifa_estado_id

        FROM tipo_pago tp

        INNER JOIN academia_tipo_pago atp
          ON atp.tipo_pago_id =
             tp.id

         AND atp.academia_id = ?

        INNER JOIN tarifas_academia ta
          ON ta.academia_id =
             atp.academia_id

         AND ta.tipo_pago_id =
             atp.tipo_pago_id

        WHERE tp.id = ?

        LIMIT 1
      `,
    [academiaId, tipoPagoId]
  );

  if (!rows?.length) {
    businessError(`El tipo de pago ${tipoPagoId} no está configurado para la academia`);
  }

  const row = rows[0];

  if (Number(row.academia_tipo_pago_estado) !== ESTADO_ACTIVO) {
    businessError(`El tipo de pago ${tipoPagoId} no está habilitado para la academia`);
  }

  if (Number(row.tarifa_estado_id) !== ESTADO_ACTIVO) {
    businessError(`La tarifa del tipo de pago ${tipoPagoId} no está activa`);
  }

  const monto = Number(row.monto);

  if (!Number.isFinite(monto) || monto < 0) {
    businessError(`La tarifa del tipo de pago ${tipoPagoId} es inválida`);
  }

  return {
    tarifa_id: Number(row.tarifa_id),

    tipo_pago_id: Number(row.tipo_pago_id),

    tipo_pago_nombre: String(row.tipo_pago_nombre ?? ""),

    monto: roundMoney(monto),
  };
}

/* =========================================================
   REGLAS DEL PLAN
========================================================= */

/**
 * Precedencia:
 *
 * 1. Regla específica para tipo_pago_id.
 * 2. Regla general del plan (tipo_pago_id NULL).
 * 3. Sin regla = sin descuento.
 */

async function getApplicablePlanRule(conn: any, planId: number | null, tipoPagoId: number) {
  if (planId === null) {
    return null;
  }

  const [rows]: any = await conn.query(
    `
        SELECT
          id,
          plan_id,
          tipo_pago_id,
          tipo_beneficio,
          valor,
          estado_id

        FROM plan_reglas

        WHERE plan_id = ?
          AND estado_id = 1

          AND (
            tipo_pago_id = ?
            OR tipo_pago_id IS NULL
          )

        ORDER BY
          CASE
            WHEN tipo_pago_id = ?
              THEN 0
            ELSE 1
          END ASC,
          id ASC

        LIMIT 1
      `,
    [planId, tipoPagoId, tipoPagoId]
  );

  return rows?.length ? rows[0] : null;
}

/* =========================================================
   CÁLCULO DE BENEFICIO
========================================================= */

function calculateBenefit(montoBase: number, rule: any | null) {
  const base = roundMoney(montoBase);

  if (!rule) {
    return {
      plan_regla_id: null,
      monto_base: base,
      monto_descuento: 0,
      monto_total: base,
    };
  }

  const tipo = String(rule.tipo_beneficio ?? "");

  const valor = Number(rule.valor);

  if (!Number.isFinite(valor) || valor < 0) {
    businessError("La regla de beneficio contiene un valor inválido");
  }

  let descuento = 0;
  let total = base;

  switch (tipo) {
    case "PORCENTAJE": {
      descuento = roundMoney(base * (valor / 100));

      descuento = Math.min(base, descuento);

      total = roundMoney(base - descuento);

      break;
    }

    case "DESCUENTO_FIJO": {
      descuento = Math.min(base, roundMoney(valor));

      total = roundMoney(base - descuento);

      break;
    }

    case "PRECIO_FIJO": {
      /*
       * Un beneficio nunca aumenta la tarifa.
       * Si el precio fijo fuese mayor al valor base,
       * se conserva el valor base.
       */
      total = Math.min(base, roundMoney(valor));

      descuento = roundMoney(base - total);

      break;
    }

    default:
      businessError("Tipo de beneficio no soportado");
  }

  return {
    plan_regla_id: Number(rule.id),

    monto_base: base,

    monto_descuento: roundMoney(descuento),

    monto_total: roundMoney(total),
  };
}

/* =========================================================
   CONSTRUIR DETALLES
========================================================= */

async function buildDetalles(
  conn: any,
  academiaId: number,
  planId: number | null,
  inputDetalles: Array<{
    tipo_pago_id: number;
    origen: "REGULAR" | "ADICIONAL";
    observaciones?: string | null;
  }>
) {
  const detalles: any[] = [];

  for (const input of inputDetalles) {
    const tarifa = await getTarifaOrThrow(conn, academiaId, Number(input.tipo_pago_id));

    const rule = await getApplicablePlanRule(conn, planId, Number(input.tipo_pago_id));

    const calculated = calculateBenefit(tarifa.monto, rule);

    detalles.push({
      tipo_pago_id: Number(input.tipo_pago_id),

      tarifa_id: tarifa.tarifa_id,

      plan_regla_id: calculated.plan_regla_id,

      monto_base: calculated.monto_base,

      monto_descuento: calculated.monto_descuento,

      monto_total: calculated.monto_total,

      origen: input.origen ?? "REGULAR",

      observaciones: cleanNullableString(input.observaciones),
    });
  }

  return detalles;
}

/* =========================================================
   TOTALES
========================================================= */

function calculateTotals(detalles: any[]) {
  const montoBase = roundMoney(detalles.reduce((acc, item) => acc + Number(item.monto_base), 0));

  const montoDescuento = roundMoney(detalles.reduce((acc, item) => acc + Number(item.monto_descuento), 0));

  const montoTotal = roundMoney(detalles.reduce((acc, item) => acc + Number(item.monto_total), 0));

  if (roundMoney(montoBase - montoDescuento) !== montoTotal) {
    businessError("Los totales del pago son inconsistentes");
  }

  return {
    monto_base: montoBase,

    monto_descuento: montoDescuento,

    monto_total: montoTotal,
  };
}

/* =========================================================
   OBTENER CABECERA
========================================================= */

async function getPagoHeader(conn: any, academiaId: number, pagoId: number) {
  const [rows]: any = await conn.query(
    `
        SELECT
          p.id,
          p.academia_id,
          p.jugador_id,
          p.sucursal_id,
          p.plan_catalogo_id,
          p.situacion_pago_id,

          p.monto_base,
          p.monto_descuento,
          p.monto_total,

          p.fecha_pago,
          p.medio_pago_id,
          p.comprobante_url,
          p.observaciones,
          p.created_at,

          j.rut_jugador
            AS jugador_rut,

          j.nombre_jugador
            AS jugador_nombre,

          j.categoria_id,

          c.nombre
            AS categoria_nombre,

          sr.nombre
            AS sucursal_nombre,

          pc.nombre
            AS plan_nombre,

          sp.nombre
            AS situacion_pago_nombre,

          mp.nombre
            AS medio_pago_nombre

        FROM pagos_jugador p

        INNER JOIN jugadores j
          ON j.id =
             p.jugador_id

         AND j.academia_id =
             p.academia_id

        LEFT JOIN categorias c
          ON c.id =
             j.categoria_id

        LEFT JOIN sucursales_real sr
          ON sr.id =
             p.sucursal_id

         AND sr.academia_id =
             p.academia_id

        LEFT JOIN planes_catalogo pc
          ON pc.id =
             p.plan_catalogo_id

        LEFT JOIN situacion_pago sp
          ON sp.id =
             p.situacion_pago_id

        LEFT JOIN medio_pago mp
          ON mp.id =
             p.medio_pago_id

        WHERE p.id = ?
          AND p.academia_id = ?

        LIMIT 1
      `,
    [pagoId, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

/* =========================================================
   DETALLES DE UN PAGO
========================================================= */

async function getPagoDetalles(conn: any, pagoId: number) {
  const [rows]: any = await conn.query(
    `
        SELECT
          pd.id,
          pd.pago_id,
          pd.tipo_pago_id,

          tp.nombre
            AS tipo_pago_nombre,

          pd.tarifa_id,
          pd.plan_regla_id,

          pd.monto_base,
          pd.monto_descuento,
          pd.monto_total,

          pd.origen,
          pd.observaciones,

          pd.created_at,
          pd.updated_at,

          pr.tipo_beneficio,
          pr.valor
            AS beneficio_valor

        FROM pago_detalle pd

        INNER JOIN tipo_pago tp
          ON tp.id =
             pd.tipo_pago_id

        LEFT JOIN plan_reglas pr
          ON pr.id =
             pd.plan_regla_id

        WHERE pd.pago_id = ?

        ORDER BY
          pd.id ASC
      `,
    [pagoId]
  );

  return rows ?? [];
}

/* =========================================================
   DETALLES PARA LISTADOS
========================================================= */

async function attachDetalles(rows: any[]) {
  if (!Array.isArray(rows) || rows.length === 0) {
    return [];
  }

  const ids = rows.map((row) => Number(row.id));

  const placeholders = ids.map(() => "?").join(", ");

  const [detailRows]: any = await db.query(
    `
        SELECT
          pd.id,
          pd.pago_id,
          pd.tipo_pago_id,

          tp.nombre
            AS tipo_pago_nombre,

          pd.tarifa_id,
          pd.plan_regla_id,

          pd.monto_base,
          pd.monto_descuento,
          pd.monto_total,

          pd.origen,
          pd.observaciones,

          pd.created_at,
          pd.updated_at,

          pr.tipo_beneficio,
          pr.valor
            AS beneficio_valor

        FROM pago_detalle pd

        INNER JOIN tipo_pago tp
          ON tp.id =
             pd.tipo_pago_id

        LEFT JOIN plan_reglas pr
          ON pr.id =
             pd.plan_regla_id

        WHERE pd.pago_id
          IN (${placeholders})

        ORDER BY
          pd.pago_id ASC,
          pd.id ASC
      `,
    ids
  );

  const byPago = new Map<number, any[]>();

  for (const detail of detailRows ?? []) {
    const pagoId = Number(detail.pago_id);

    if (!byPago.has(pagoId)) {
      byPago.set(pagoId, []);
    }

    byPago.get(pagoId)!.push(detail);
  }

  return rows.map((row) => ({
    ...row,

    detalles: byPago.get(Number(row.id)) ?? [],
  }));
}

/* =========================================================
   INSERTAR DETALLES
========================================================= */

async function insertDetalles(conn: any, pagoId: number, detalles: any[]) {
  for (const detalle of detalles) {
    await conn.query(
      `
        INSERT INTO pago_detalle (
          pago_id,
          tipo_pago_id,
          tarifa_id,
          plan_regla_id,
          monto_base,
          monto_descuento,
          monto_total,
          origen,
          observaciones
        )

        VALUES (
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          ?
        )
      `,
      [
        pagoId,
        detalle.tipo_pago_id,
        detalle.tarifa_id,
        detalle.plan_regla_id,
        detalle.monto_base,
        detalle.monto_descuento,
        detalle.monto_total,
        detalle.origen,
        detalle.observaciones,
      ]
    );
  }
}

/* =========================================================
   QUERY BASE
========================================================= */

const PAYMENT_SELECT = `
  SELECT
    p.id,
    p.academia_id,
    p.jugador_id,
    p.sucursal_id,
    p.plan_catalogo_id,
    p.situacion_pago_id,

    p.monto_base,
    p.monto_descuento,
    p.monto_total,

    p.fecha_pago,
    p.medio_pago_id,
    p.comprobante_url,
    p.observaciones,
    p.created_at,

    j.rut_jugador
      AS jugador_rut,

    j.nombre_jugador
      AS jugador_nombre,

    j.categoria_id,

    c.nombre
      AS categoria_nombre,

    sr.nombre
      AS sucursal_nombre,

    pc.nombre
      AS plan_nombre,

    sp.nombre
      AS situacion_pago_nombre,

    mp.nombre
      AS medio_pago_nombre

  FROM pagos_jugador p

  INNER JOIN jugadores j
    ON j.id =
       p.jugador_id

   AND j.academia_id =
       p.academia_id

  LEFT JOIN categorias c
    ON c.id =
       j.categoria_id

  LEFT JOIN sucursales_real sr
    ON sr.id =
       p.sucursal_id

   AND sr.academia_id =
       p.academia_id

  LEFT JOIN planes_catalogo pc
    ON pc.id =
       p.plan_catalogo_id

  LEFT JOIN situacion_pago sp
    ON sp.id =
       p.situacion_pago_id

  LEFT JOIN medio_pago mp
    ON mp.id =
       p.medio_pago_id
`;

/* =========================================================
   ROUTER
========================================================= */

export default async function pagos_jugador(app: FastifyInstance) {
  /**
   * FINANZAS
   *
   * Seguridad conservada:
   *
   * READ:
   * - Admin
   * - Superadmin
   *
   * WRITE:
   * - Admin
   * - Superadmin
   */

  const canRead = [requireAuth, requireRoles([1, 3])];

  const canWrite = [requireAuth, requireRoles([1, 3])];

  /* =======================================================
     HEALTH
  ======================================================= */

  app.get(
    "/health",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const academia_id = resolveAcademiaId(req);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          module: "pagos_jugador",

          status: "ready",

          timestamp: new Date().toISOString(),

          academia_id,
        });
      } catch (err: any) {
        const code = getStatusCode(err);

        reply.header("Cache-Control", "no-store");

        return reply.code(code).send({
          ok: false,

          message: "Error /health pagos_jugador",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     GET /
     LISTADO + FILTROS + PAGINACIÓN
  ======================================================= */

  app.get(
    "/",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const queryParsed = ListQuery.safeParse((req as any).query);

      if (!queryParsed.success) {
        reply.header("Cache-Control", "no-store");

        return reply.code(400).send({
          ok: false,

          message: "Query inválida",

          errors: queryParsed.error.flatten(),
        });
      }

      const {
        limit,
        offset,
        year,
        month,
        tipo_pago_id,
        jugador_rut,
        jugador_id,
        sucursal_id,
        plan_catalogo_id,
        situacion_pago_id,
      } = queryParsed.data;

      try {
        const academia_id = resolveAcademiaId(req);

        let sql =
          PAYMENT_SELECT +
          `
            WHERE
              p.academia_id = ?
          `;

        const params: any[] = [academia_id];

        if (jugador_rut) {
          sql += `
            AND j.rut_jugador = ?
          `;

          params.push(jugador_rut);
        }

        if (jugador_id) {
          sql += `
            AND p.jugador_id = ?
          `;

          params.push(jugador_id);
        }

        if (sucursal_id) {
          sql += `
            AND p.sucursal_id = ?
          `;

          params.push(sucursal_id);
        }

        if (plan_catalogo_id) {
          sql += `
            AND p.plan_catalogo_id = ?
          `;

          params.push(plan_catalogo_id);
        }

        if (situacion_pago_id) {
          sql += `
            AND p.situacion_pago_id = ?
          `;

          params.push(situacion_pago_id);
        }

        if (tipo_pago_id) {
          sql += `
            AND EXISTS (
              SELECT 1

              FROM pago_detalle pd_filter

              WHERE pd_filter.pago_id =
                    p.id

                AND pd_filter.tipo_pago_id = ?
            )
          `;

          params.push(tipo_pago_id);
        }

        if (year) {
          sql += `
            AND YEAR(p.fecha_pago) = ?
          `;

          params.push(year);
        }

        if (month) {
          sql += `
            AND MONTH(p.fecha_pago) = ?
          `;

          params.push(month);
        }

        sql += `
          ORDER BY
            p.fecha_pago DESC,
            p.id DESC

          LIMIT ?
          OFFSET ?
        `;

        params.push(limit, offset);

        const [rows]: any = await db.query(sql, params);

        const items = await attachDetalles(rows ?? []);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          academia_id,

          items,

          limit,
          offset,

          filters: {
            year,
            month,
            tipo_pago_id,
            jugador_rut,
            jugador_id,
            sucursal_id,
            plan_catalogo_id,
            situacion_pago_id,
          },
        });
      } catch (err: any) {
        const code = getStatusCode(err);

        reply.header("Cache-Control", "no-store");

        return reply.code(code).send({
          ok: false,

          message: "Error al listar pagos",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     GET /estado-cuenta
  ======================================================= */

  app.get(
    "/estado-cuenta",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const academia_id = resolveAcademiaId(req);

        const [rows]: any = await db.query(
          PAYMENT_SELECT +
            `
                WHERE
                  p.academia_id = ?

                ORDER BY
                  p.fecha_pago DESC,
                  p.id DESC
              `,
          [academia_id]
        );

        const items = await attachDetalles(rows ?? []);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          academia_id,

          items,
        });
      } catch (err: any) {
        const code = getStatusCode(err);

        reply.header("Cache-Control", "no-store");

        return reply.code(code).send({
          ok: false,

          message: "Error al obtener estado de cuenta",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     GET /jugador/:jugador_rut
     SE CONSERVA RUTA POR COMPATIBILIDAD
  ======================================================= */

  app.get(
    "/jugador/:jugador_rut",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = RutParam.safeParse((req as any).params);

      if (!parsed.success) {
        reply.header("Cache-Control", "no-store");

        return reply.code(400).send({
          ok: false,
          message: "RUT inválido",
        });
      }

      try {
        const academia_id = resolveAcademiaId(req);

        /*
         * Validación explícita de tenant.
         */
        await getJugadorByRutOrThrow(db, academia_id, parsed.data.jugador_rut);

        const [rows]: any = await db.query(
          PAYMENT_SELECT +
            `
                WHERE
                  p.academia_id = ?

                  AND j.rut_jugador = ?

                ORDER BY
                  p.fecha_pago DESC,
                  p.id DESC
              `,
          [academia_id, parsed.data.jugador_rut]
        );

        const items = await attachDetalles(rows ?? []);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          academia_id,

          items,
        });
      } catch (err: any) {
        const code = getStatusCode(err);

        reply.header("Cache-Control", "no-store");

        return reply.code(code).send({
          ok: false,

          message: err?.message === "FORBIDDEN_JUGADOR" ? "FORBIDDEN_JUGADOR" : "Error al listar pagos por jugador",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     GET /:id
  ======================================================= */

  app.get(
    "/:id",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse((req as any).params);

      if (!parsed.success) {
        reply.header("Cache-Control", "no-store");

        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      try {
        const academia_id = resolveAcademiaId(req);

        const item = await getPagoHeader(db, academia_id, parsed.data.id);

        reply.header("Cache-Control", "no-store");

        if (!item) {
          return reply.code(404).send({
            ok: false,

            message: "Pago no encontrado",
          });
        }

        const detalles = await getPagoDetalles(db, parsed.data.id);

        return reply.send({
          ok: true,

          academia_id,

          item: {
            ...item,
            detalles,
          },
        });
      } catch (err: any) {
        const code = getStatusCode(err);

        reply.header("Cache-Control", "no-store");

        return reply.code(code).send({
          ok: false,

          message: "Error al obtener pago",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     POST /
     CREAR TRANSACCIÓN COMPLETA
  ======================================================= */

  app.post(
    "/",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = CreateSchema.safeParse((req as any).body ?? {});

      if (!parsed.success) {
        reply.header("Cache-Control", "no-store");

        return reply.code(400).send({
          ok: false,

          message: "Payload inválido",

          errors: parsed.error.flatten(),
        });
      }

      const data = parsed.data;

      const fechaPago = toSQLDate(String(data.fecha_pago));

      if (!fechaPago) {
        reply.header("Cache-Control", "no-store");

        return reply.code(400).send({
          ok: false,

          message: "fecha_pago inválida",
        });
      }

      const conn = await db.getConnection();

      let transactionStarted = false;

      try {
        const academia_id = resolveAcademiaId(req);

        await conn.beginTransaction();

        transactionStarted = true;

        /* -----------------------------
           JUGADOR
        ----------------------------- */

        await getJugadorOrThrow(conn, academia_id, data.jugador_id);

        /* -----------------------------
           SUCURSAL
        ----------------------------- */

        await assertSucursalOrThrow(conn, academia_id, data.jugador_id, data.sucursal_id);

        /* -----------------------------
           CATÁLOGOS
        ----------------------------- */

        await assertSituacionPagoOrThrow(conn, data.situacion_pago_id);

        await assertMedioPagoOrThrow(conn, data.medio_pago_id);

        /* -----------------------------
           PLAN
        ----------------------------- */

        await assertPlanForPaymentOrThrow(conn, academia_id, data.jugador_id, data.plan_catalogo_id, fechaPago);

        /* -----------------------------
           CONCEPTOS
        ----------------------------- */

        const detalles = await buildDetalles(conn, academia_id, data.plan_catalogo_id, data.detalles);

        const totals = calculateTotals(detalles);

        /*
         * Si existe descuento,
         * necesariamente debe existir
         * un plan_catalogo_id.
         */
        if (totals.monto_descuento > 0 && data.plan_catalogo_id === null) {
          businessError("No puede registrarse un descuento sin un plan asociado");
        }

        /* -----------------------------
           CABECERA
        ----------------------------- */

        const [result]: any = await conn.query(
          `
              INSERT INTO pagos_jugador (
                academia_id,
                jugador_id,
                sucursal_id,
                plan_catalogo_id,
                situacion_pago_id,
                monto_base,
                monto_descuento,
                monto_total,
                fecha_pago,
                medio_pago_id,
                comprobante_url,
                observaciones
              )

              VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?
              )
            `,
          [
            academia_id,
            data.jugador_id,
            data.sucursal_id,
            data.plan_catalogo_id,
            data.situacion_pago_id,
            totals.monto_base,
            totals.monto_descuento,
            totals.monto_total,
            fechaPago,
            data.medio_pago_id,
            cleanNullableString(data.comprobante_url),
            cleanNullableString(data.observaciones),
          ]
        );

        const pagoId = Number(result?.insertId);

        if (!Number.isInteger(pagoId) || pagoId <= 0) {
          throw new Error("No fue posible obtener el ID del pago creado");
        }

        /* -----------------------------
           DETALLES
        ----------------------------- */

        await insertDetalles(conn, pagoId, detalles);

        await conn.commit();

        transactionStarted = false;

        const item = await getPagoHeader(conn, academia_id, pagoId);

        const storedDetalles = await getPagoDetalles(conn, pagoId);

        reply.header("Cache-Control", "no-store");

        return reply.code(201).send({
          ok: true,

          academia_id,

          id: pagoId,

          item: item
            ? {
                ...item,
                detalles: storedDetalles,
              }
            : {
                id: pagoId,

                academia_id,

                jugador_id: data.jugador_id,

                sucursal_id: data.sucursal_id,

                plan_catalogo_id: data.plan_catalogo_id,

                situacion_pago_id: data.situacion_pago_id,

                monto_base: totals.monto_base,

                monto_descuento: totals.monto_descuento,

                monto_total: totals.monto_total,

                fecha_pago: fechaPago,

                medio_pago_id: data.medio_pago_id,

                comprobante_url: cleanNullableString(data.comprobante_url),

                observaciones: cleanNullableString(data.observaciones),

                detalles: storedDetalles,
              },
        });
      } catch (err: any) {
        if (transactionStarted) {
          try {
            await conn.rollback();
          } catch {}
        }

        const code = getStatusCode(err);

        reply.header("Cache-Control", "no-store");

        return reply.code(code).send({
          ok: false,

          message:
            err?.message === "FORBIDDEN_JUGADOR"
              ? "FORBIDDEN_JUGADOR"
              : err?.statusCode
                ? err.message
                : "Error al crear pago",

          detail: err?.message,
        });
      } finally {
        conn.release();
      }
    }
  );

  /* =======================================================
     PUT /:id
     ACTUALIZACIÓN PARCIAL CONSERVANDO COMPORTAMIENTO
     DEL ROUTER ANTERIOR
  ======================================================= */

  app.put(
    "/:id",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const pid = IdParam.safeParse((req as any).params);

      if (!pid.success) {
        reply.header("Cache-Control", "no-store");

        return reply.code(400).send({
          ok: false,

          message: "ID inválido",
        });
      }

      const parsed = UpdateSchema.safeParse((req as any).body ?? {});

      if (!parsed.success) {
        reply.header("Cache-Control", "no-store");

        return reply.code(400).send({
          ok: false,

          message: "Payload inválido",

          errors: parsed.error.flatten(),
        });
      }

      if (Object.keys(parsed.data).length === 0) {
        reply.header("Cache-Control", "no-store");

        return reply.code(400).send({
          ok: false,

          message: "No hay campos para actualizar",
        });
      }

      const id = pid.data.id;

      const conn = await db.getConnection();

      let transactionStarted = false;

      try {
        const academia_id = resolveAcademiaId(req);

        await conn.beginTransaction();

        transactionStarted = true;

        const current = await getPagoHeader(conn, academia_id, id);

        if (!current) {
          await conn.rollback();

          transactionStarted = false;

          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Pago no encontrado",
          });
        }

        const body = parsed.data;

        const jugadorId = body.jugador_id ?? Number(current.jugador_id);

        const sucursalId =
          body.sucursal_id !== undefined
            ? body.sucursal_id
            : current.sucursal_id == null
              ? null
              : Number(current.sucursal_id);

        const planId =
          body.plan_catalogo_id !== undefined
            ? body.plan_catalogo_id
            : current.plan_catalogo_id == null
              ? null
              : Number(current.plan_catalogo_id);

        const situacionPagoId = body.situacion_pago_id ?? Number(current.situacion_pago_id);

        const medioPagoId = body.medio_pago_id ?? Number(current.medio_pago_id);

        let fechaPago =
          body.fecha_pago !== undefined ? toSQLDate(body.fecha_pago) : String(current.fecha_pago).slice(0, 10);

        if (!fechaPago) {
          businessError("fecha_pago inválida");
        }

        await getJugadorOrThrow(conn, academia_id, jugadorId);

        await assertSucursalOrThrow(conn, academia_id, jugadorId, sucursalId);

        await assertSituacionPagoOrThrow(conn, situacionPagoId);

        await assertMedioPagoOrThrow(conn, medioPagoId);

        await assertPlanForPaymentOrThrow(conn, academia_id, jugadorId, planId, fechaPago);

        let montoBase = Number(current.monto_base);

        let montoDescuento = Number(current.monto_descuento);

        let montoTotal = Number(current.monto_total);

        /*
         * Los conceptos se recalculan solamente cuando:
         *
         * - frontend envía detalles nuevos, o
         * - cambia plan_catalogo_id.
         *
         * Así una modificación administrativa
         * (situación, comprobante, observación, etc.)
         * NO recalcula una tarifa histórica.
         */
        const recalculateDetalles = body.detalles !== undefined || body.plan_catalogo_id !== undefined;

        if (recalculateDetalles) {
          let requestedDetalles: Array<{
            tipo_pago_id: number;
            origen: "REGULAR" | "ADICIONAL";
            observaciones?: string | null;
          }>;

          if (body.detalles !== undefined) {
            requestedDetalles = body.detalles;
          } else {
            const currentDetalles = await getPagoDetalles(conn, id);

            requestedDetalles = currentDetalles.map((detalle: any) => ({
              tipo_pago_id: Number(detalle.tipo_pago_id),

              origen: String(detalle.origen) === "ADICIONAL" ? "ADICIONAL" : "REGULAR",

              observaciones: detalle.observaciones ?? null,
            }));
          }

          const nuevosDetalles = await buildDetalles(conn, academia_id, planId, requestedDetalles);

          const totals = calculateTotals(nuevosDetalles);

          montoBase = totals.monto_base;

          montoDescuento = totals.monto_descuento;

          montoTotal = totals.monto_total;

          if (montoDescuento > 0 && planId === null) {
            businessError("No puede registrarse un descuento sin un plan asociado");
          }

          await conn.query(
            `
              DELETE
              FROM pago_detalle

              WHERE pago_id = ?
            `,
            [id]
          );

          await insertDetalles(conn, id, nuevosDetalles);
        }

        await conn.query(
          `
            UPDATE pagos_jugador

            SET
              jugador_id = ?,
              sucursal_id = ?,
              plan_catalogo_id = ?,
              situacion_pago_id = ?,
              monto_base = ?,
              monto_descuento = ?,
              monto_total = ?,
              fecha_pago = ?,
              medio_pago_id = ?,
              comprobante_url = ?,
              observaciones = ?

            WHERE id = ?
              AND academia_id = ?

            LIMIT 1
          `,
          [
            jugadorId,
            sucursalId,
            planId,
            situacionPagoId,
            montoBase,
            montoDescuento,
            montoTotal,
            fechaPago,
            medioPagoId,

            body.comprobante_url !== undefined ? cleanNullableString(body.comprobante_url) : current.comprobante_url,

            body.observaciones !== undefined ? cleanNullableString(body.observaciones) : current.observaciones,

            id,
            academia_id,
          ]
        );

        await conn.commit();

        transactionStarted = false;

        const updated = await getPagoHeader(conn, academia_id, id);

        const detalles = await getPagoDetalles(conn, id);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          academia_id,

          updated: updated
            ? {
                ...updated,
                detalles,
              }
            : {
                id,
              },
        });
      } catch (err: any) {
        if (transactionStarted) {
          try {
            await conn.rollback();
          } catch {}
        }

        const code = getStatusCode(err);

        reply.header("Cache-Control", "no-store");

        return reply.code(code).send({
          ok: false,

          message:
            err?.message === "FORBIDDEN_JUGADOR"
              ? "FORBIDDEN_JUGADOR"
              : err?.statusCode
                ? err.message
                : "Error al actualizar pago",

          detail: err?.message,
        });
      } finally {
        conn.release();
      }
    }
  );

  /* =======================================================
     DELETE /:id
  ======================================================= */

  app.delete(
    "/:id",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse((req as any).params);

      if (!parsed.success) {
        reply.header("Cache-Control", "no-store");

        return reply.code(400).send({
          ok: false,

          message: "ID inválido",
        });
      }

      const conn = await db.getConnection();

      let transactionStarted = false;

      try {
        const academia_id = resolveAcademiaId(req);

        const pagoId = parsed.data.id;

        const current = await getPagoHeader(conn, academia_id, pagoId);

        if (!current) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Pago no encontrado",
          });
        }

        await conn.beginTransaction();

        transactionStarted = true;

        /*
         * pago_detalle tiene FK RESTRICT hacia
         * pagos_jugador, por lo que primero
         * eliminamos los detalles.
         */
        await conn.query(
          `
            DELETE
            FROM pago_detalle

            WHERE pago_id = ?
          `,
          [pagoId]
        );

        const [result]: any = await conn.query(
          `
              DELETE
              FROM pagos_jugador

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [pagoId, academia_id]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          businessError("Pago no encontrado", 404);
        }

        await conn.commit();

        transactionStarted = false;

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          academia_id,

          deleted: pagoId,
        });
      } catch (err: any) {
        if (transactionStarted) {
          try {
            await conn.rollback();
          } catch {}
        }

        const code = getStatusCode(err);

        reply.header("Cache-Control", "no-store");

        return reply.code(code).send({
          ok: false,

          message: err?.statusCode ? err.message : "Error al eliminar pago",

          detail: err?.message,
        });
      } finally {
        conn.release();
      }
    }
  );
}
