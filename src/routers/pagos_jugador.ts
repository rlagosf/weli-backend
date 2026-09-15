// src/routers/pagos_jugador.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * =========================================================
 * WELI - PAGOS DE JUGADORES
 * =========================================================
 *
 * MODELO ACTUAL:
 *
 * tarifas_academia
 *      │
 *      ▼
 * jugador_plan_catalogo
 *      │
 *      ├── monto_tarifa
 *      └── monto_asignado  ← BASE HABITUAL DEL JUGADOR
 *               │
 *               ▼
 *         pago_detalle
 *               │
 *               ├── monto_base
 *               ├── monto_descuento
 *               └── monto_total
 *
 * REGLA:
 *
 * REGULAR:
 * - monto_base = jugador_plan_catalogo.monto_asignado.
 * - NO se vuelve a calcular el beneficio inicial.
 *
 * ADICIONAL:
 * - si existe configuración vigente del jugador para el tipo de pago,
 *   también usa monto_asignado.
 * - si no existe, usa la tarifa activa actual de la academia.
 *
 * BENEFICIO DE LA TRANSACCIÓN:
 *
 * pagos_jugador.plan_catalogo_id se interpreta como un beneficio
 * ADICIONAL y puntual de la transacción.
 *
 * Ejemplo:
 *
 * tarifa academia         30.000
 * beneficio inscripción      50 %
 * monto_asignado           15.000
 *
 * beneficio transacción       20 %
 * pago_detalle.monto_base  15.000
 * monto_descuento           3.000
 * monto_total              12.000
 *
 * pago_detalle conserva el snapshot de la transacción.
 *
 * Seguridad:
 * READ  -> roles 1,3
 * WRITE -> roles 1,3
 *
 * academia_id nunca se recibe desde body.
 * =========================================================
 */

const ESTADO_ACTIVO = 1;
const MAX_DETALLES_PAGO = 50;

/* =========================================================
   HELPERS
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

function cleanNullableString(value: unknown): string | null {
  if (value === null || value === undefined) return null;

  const text = String(value).trim();
  return text || null;
}

/* =========================================================
   FECHAS
========================================================= */

function toSQLDate(input: string): string | null {
  if (!input) return null;

  if (/^\d{4}-\d{2}-\d{2}$/.test(input)) {
    const parsed = new Date(`${input}T00:00:00Z`);
    return Number.isNaN(parsed.getTime()) ? null : input;
  }

  const parsed = new Date(input);

  if (Number.isNaN(parsed.getTime())) {
    return null;
  }

  return parsed.toISOString().slice(0, 10);
}

function normalizeSQLDate(value: any): string | null {
  if (value === null || value === undefined) return null;

  if (typeof value === "string") {
    const match = value.match(/^(\d{4}-\d{2}-\d{2})/);
    if (match) return match[1];
  }

  if (value instanceof Date && !Number.isNaN(value.getTime())) {
    return value.toISOString().slice(0, 10);
  }

  const parsed = new Date(value);

  if (Number.isNaN(parsed.getTime())) {
    return null;
  }

  return parsed.toISOString().slice(0, 10);
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

    /*
     * Beneficio EXTRA de esta transacción.
     *
     * null:
     *   cobra monto_asignado sin descuento extra.
     *
     * ID:
     *   aplica plan_reglas SOBRE monto_asignado.
     */
    plan_catalogo_id: z.union([z.coerce.number().int().positive(), z.null()]).optional().default(null),

    situacion_pago_id: z.coerce.number().int().positive(),

    fecha_pago: z.string().min(10),

    medio_pago_id: z.coerce.number().int().positive(),

    comprobante_url: z.string().url().nullable().optional(),

    observaciones: z.string().nullable().optional(),

    detalles: z.array(DetalleSchema).min(1, "Debe registrar al menos un concepto de pago").max(MAX_DETALLES_PAGO),
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

    detalles: z.array(DetalleSchema).min(1).max(MAX_DETALLES_PAGO).optional(),
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
   VALIDACIONES BÁSICAS
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

async function assertSucursalOrThrow(conn: any, academiaId: number, jugadorId: number, sucursalId: number | null) {
  if (sucursalId === null) return;

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

  const [relationRows]: any = await conn.query(
    `
    SELECT
      js.id

    FROM jugador_sucursal js

    INNER JOIN jugadores j
      ON j.id = js.jugador_id
     AND j.academia_id = ?

    INNER JOIN sucursales_real sr
      ON sr.id = js.sucursal_id
     AND sr.academia_id = ?

    WHERE js.jugador_id = ?
      AND js.sucursal_id = ?

    LIMIT 1
  `,
    [academiaId, academiaId, jugadorId, sucursalId]
  );

  if (!relationRows?.length) {
    businessError("El jugador no pertenece a la sucursal seleccionada");
  }
}

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

function assertDistinctDetalles(detalles: Array<{ tipo_pago_id: number }>) {
  const ids = detalles.map((item) => Number(item.tipo_pago_id));

  if (new Set(ids).size !== ids.length) {
    businessError("No puede repetirse el mismo tipo de pago dentro de una misma transacción");
  }
}

/* =========================================================
   COMPATIBILIDAD DE ESQUEMA pagos_jugador
========================================================= */

type ColumnMeta = {
  Field: string;
  Null: "YES" | "NO" | string;
  Default: any;
  Extra: string;
};

async function getPagosJugadorColumns(conn: any): Promise<Map<string, ColumnMeta>> {
  const [rows]: any = await conn.query("SHOW COLUMNS FROM pagos_jugador");

  return new Map((rows ?? []).map((row: ColumnMeta) => [String(row.Field), row]));
}

function assertRequiredColumnsCovered(columns: Map<string, ColumnMeta>, payload: Record<string, any>) {
  const missing: string[] = [];

  for (const [name, meta] of columns.entries()) {
    if (
      String(meta.Extra ?? "")
        .toLowerCase()
        .includes("auto_increment")
    ) {
      continue;
    }

    const required = meta.Null === "NO" && meta.Default == null;

    if (required && !(name in payload)) {
      missing.push(name);
    }
  }

  if (missing.length > 0) {
    businessError(
      `La tabla pagos_jugador conserva columnas obligatorias no cubiertas por el modelo actual: ${missing.join(", ")}. Revise la migración antes de registrar pagos.`,
      500
    );
  }
}

function pickExistingColumns(columns: Map<string, ColumnMeta>, source: Record<string, any>) {
  const payload: Record<string, any> = {};

  for (const [key, value] of Object.entries(source)) {
    if (columns.has(key)) {
      payload[key] = value;
    }
  }

  return payload;
}

async function insertPagoHeaderCompat(
  conn: any,
  input: {
    academia_id: number;
    jugador_id: number;
    jugador_rut: number;
    sucursal_id: number | null;
    plan_catalogo_id: number | null;
    situacion_pago_id: number;
    monto_base: number;
    monto_descuento: number;
    monto_total: number;
    fecha_pago: string;
    medio_pago_id: number;
    comprobante_url: string | null;
    observaciones: string | null;
    tipo_pago_id: number;
  }
) {
  const columns = await getPagosJugadorColumns(conn);

  /*
   * Además del modelo nuevo se rellenan, solo si todavía existen,
   * las columnas legacy jugador_rut / tipo_pago_id / monto.
   * Esto permite convivir con la migración progresiva sin volver
   * a depender de esas columnas para la lógica financiera.
   */
  const source = {
    academia_id: input.academia_id,
    jugador_id: input.jugador_id,
    jugador_rut: input.jugador_rut,
    sucursal_id: input.sucursal_id,
    plan_catalogo_id: input.plan_catalogo_id,
    situacion_pago_id: input.situacion_pago_id,
    monto_base: input.monto_base,
    monto_descuento: input.monto_descuento,
    monto_total: input.monto_total,
    monto: input.monto_total,
    tipo_pago_id: input.tipo_pago_id,
    fecha_pago: input.fecha_pago,
    medio_pago_id: input.medio_pago_id,
    comprobante_url: input.comprobante_url,
    observaciones: input.observaciones,
  };

  const payload = pickExistingColumns(columns, source);

  assertRequiredColumnsCovered(columns, payload);

  const names = Object.keys(payload);

  if (names.length === 0) {
    businessError("No existen columnas compatibles para insertar el pago", 500);
  }

  const sql = `
    INSERT INTO pagos_jugador (
      ${names.map((name) => `\`${name}\``).join(", ")}
    )
    VALUES (${names.map(() => "?").join(", ")})
  `;

  const values = names.map((name) => payload[name]);

  const [result]: any = await conn.query(sql, values);

  return result;
}

async function updatePagoHeaderCompat(
  conn: any,
  pagoId: number,
  academiaId: number,
  input: {
    jugador_id: number;
    jugador_rut: number;
    sucursal_id: number | null;
    plan_catalogo_id: number | null;
    situacion_pago_id: number;
    monto_base: number;
    monto_descuento: number;
    monto_total: number;
    fecha_pago: string;
    medio_pago_id: number;
    comprobante_url: string | null;
    observaciones: string | null;
    tipo_pago_id: number;
  }
) {
  const columns = await getPagosJugadorColumns(conn);

  const source = {
    jugador_id: input.jugador_id,
    jugador_rut: input.jugador_rut,
    sucursal_id: input.sucursal_id,
    plan_catalogo_id: input.plan_catalogo_id,
    situacion_pago_id: input.situacion_pago_id,
    monto_base: input.monto_base,
    monto_descuento: input.monto_descuento,
    monto_total: input.monto_total,
    monto: input.monto_total,
    tipo_pago_id: input.tipo_pago_id,
    fecha_pago: input.fecha_pago,
    medio_pago_id: input.medio_pago_id,
    comprobante_url: input.comprobante_url,
    observaciones: input.observaciones,
  };

  const payload = pickExistingColumns(columns, source);
  const names = Object.keys(payload);

  if (names.length === 0) {
    businessError("No existen columnas compatibles para actualizar el pago", 500);
  }

  const sql = `
    UPDATE pagos_jugador
    SET ${names.map((name) => `\`${name}\` = ?`).join(", ")}
    WHERE id = ?
      AND academia_id = ?
    LIMIT 1
  `;

  const values = names.map((name) => payload[name]);
  values.push(pagoId, academiaId);

  const [result]: any = await conn.query(sql, values);

  return result;
}

/* =========================================================
   TARIFA ACTUAL DE ACADEMIA
   SOLO FALLBACK PARA ORIGEN ADICIONAL
========================================================= */

async function getTarifaActualOrThrow(conn: any, academiaId: number, tipoPagoId: number) {
  const [rows]: any = await conn.query(
    `
      SELECT
        tp.id AS tipo_pago_id,
        tp.nombre AS tipo_pago_nombre,
        tp.estado_id AS tipo_pago_estado_id,

        atp.estado_id AS academia_tipo_pago_estado,

        ta.id AS tarifa_id,
        ta.monto,
        ta.estado_id AS tarifa_estado_id

      FROM tipo_pago tp

      INNER JOIN academia_tipo_pago atp
        ON atp.tipo_pago_id = tp.id
       AND atp.academia_id = ?

      INNER JOIN tarifas_academia ta
        ON ta.academia_id = atp.academia_id
       AND ta.tipo_pago_id = atp.tipo_pago_id

      WHERE tp.id = ?

      LIMIT 1
    `,
    [academiaId, tipoPagoId]
  );

  if (!rows?.length) {
    businessError(`El tipo de pago ${tipoPagoId} no está configurado para la academia`);
  }

  const row = rows[0];

  if (Number(row.tipo_pago_estado_id) !== ESTADO_ACTIVO) {
    businessError(`El tipo de pago ${tipoPagoId} no se encuentra activo`);
  }

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
   CONFIGURACIÓN FINANCIERA VIGENTE DEL JUGADOR
========================================================= */

/**
 * Devuelve el snapshot financiero asignado al jugador
 * para un tipo de pago y una fecha.
 *
 * IMPORTANTE:
 * monto_asignado es la base regular del cobro.
 */
async function getJugadorTipoPagoConfig(
  conn: any,
  academiaId: number,
  jugadorId: number,
  tipoPagoId: number,
  fechaPago: string
) {
  const [rows]: any = await conn.query(
    `
      SELECT
        jpc.id AS jugador_plan_catalogo_id,
        jpc.tipo_pago_id,
        jpc.plan_id,
        jpc.tarifa_id,
        jpc.monto_tarifa,
        jpc.monto_asignado,
        jpc.fecha_inicio,
        jpc.fecha_fin,

        tp.nombre AS tipo_pago_nombre,

        pc.nombre AS plan_nombre

      FROM jugador_plan_catalogo jpc

      INNER JOIN tipo_pago tp
        ON tp.id = jpc.tipo_pago_id

      INNER JOIN planes_catalogo pc
        ON pc.id = jpc.plan_id

      WHERE jpc.academia_id = ?
        AND jpc.jugador_id = ?
        AND jpc.tipo_pago_id = ?
        AND jpc.estado_id = 1

        AND jpc.fecha_inicio <= ?

        AND (
          jpc.fecha_fin IS NULL
          OR jpc.fecha_fin >= ?
        )

      ORDER BY
        jpc.fecha_inicio DESC,
        jpc.id DESC

      LIMIT 1
    `,
    [academiaId, jugadorId, tipoPagoId, fechaPago, fechaPago]
  );

  if (!rows?.length) {
    return null;
  }

  const row = rows[0];

  const montoTarifa = Number(row.monto_tarifa);
  const montoAsignado = Number(row.monto_asignado);

  if (!Number.isFinite(montoTarifa) || montoTarifa < 0) {
    businessError("La tarifa histórica asignada al jugador es inválida");
  }

  if (!Number.isFinite(montoAsignado) || montoAsignado < 0) {
    businessError("El monto asignado al jugador es inválido");
  }

  if (montoAsignado > montoTarifa) {
    businessError("El monto asignado no puede superar la tarifa histórica");
  }

  return {
    jugador_plan_catalogo_id: Number(row.jugador_plan_catalogo_id),
    tipo_pago_id: Number(row.tipo_pago_id),
    tipo_pago_nombre: String(row.tipo_pago_nombre ?? ""),
    plan_id: Number(row.plan_id),
    plan_nombre: String(row.plan_nombre ?? ""),
    tarifa_id: Number(row.tarifa_id),
    monto_tarifa: roundMoney(montoTarifa),
    monto_asignado: roundMoney(montoAsignado),
    fecha_inicio: normalizeSQLDate(row.fecha_inicio),
    fecha_fin: normalizeSQLDate(row.fecha_fin),
  };
}

/* =========================================================
   BENEFICIO EXTRA DE LA TRANSACCIÓN
========================================================= */

/**
 * plan_catalogo_id de pagos_jugador ya NO representa
 * el beneficio habitual del jugador.
 *
 * Representa únicamente un beneficio EXTRA aplicado
 * sobre monto_asignado dentro de esta transacción.
 *
 * No exige que el plan esté asignado previamente al jugador.
 * Sí exige que exista y esté activo globalmente.
 */
async function assertTransactionPlanOrThrow(conn: any, planId: number | null) {
  if (planId === null) {
    return null;
  }

  const [rows]: any = await conn.query(
    `
      SELECT
        id,
        nombre,
        descripcion,
        estado_id

      FROM planes_catalogo

      WHERE id = ?

      LIMIT 1
    `,
    [planId]
  );

  if (!rows?.length) {
    businessError("El beneficio adicional seleccionado no existe");
  }

  if (Number(rows[0].estado_id) !== ESTADO_ACTIVO) {
    businessError("El beneficio adicional seleccionado no se encuentra activo");
  }

  return rows[0];
}

async function getPlanRule(conn: any, planId: number | null) {
  if (planId === null) {
    return null;
  }

  const [rows]: any = await conn.query(
    `
      SELECT
        id,
        plan_id,
        tipo_beneficio,
        valor,
        estado_id

      FROM plan_reglas

      WHERE plan_id = ?
        AND estado_id = 1

      LIMIT 1
    `,
    [planId]
  );

  /*
   * SIN BENEFICIO puede no tener regla.
   */
  return rows?.length ? rows[0] : null;
}

function calculateBenefit(montoBase: number, rule: any | null) {
  const base = roundMoney(montoBase);

  if (!Number.isFinite(base) || base < 0) {
    businessError("El monto base de la transacción es inválido");
  }

  if (!rule) {
    return {
      plan_regla_id: null,
      monto_base: base,
      monto_descuento: 0,
      monto_total: base,
    };
  }

  const tipo = String(rule.tipo_beneficio ?? "")
    .trim()
    .toUpperCase();

  const valor = Number(rule.valor);

  if (!Number.isFinite(valor) || valor < 0) {
    businessError("La regla de beneficio contiene un valor inválido");
  }

  let descuento = 0;
  let total = base;

  switch (tipo) {
    case "PORCENTAJE": {
      if (valor > 100) {
        businessError("El porcentaje del beneficio no puede ser superior a 100");
      }

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
       * Un beneficio adicional nunca puede aumentar
       * el monto previamente asignado.
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

/**
 * REGULAR:
 * 1. exige configuración vigente en jugador_plan_catalogo.
 * 2. usa monto_asignado como monto_base.
 *
 * ADICIONAL:
 * 1. si existe configuración vigente, usa monto_asignado.
 * 2. si no existe, usa tarifa actual de academia.
 *
 * Luego aplica, si corresponde, el beneficio adicional
 * de la transacción SOBRE esa base.
 */
async function buildDetalles(
  conn: any,
  academiaId: number,
  jugadorId: number,
  fechaPago: string,
  transactionPlanId: number | null,
  inputDetalles: Array<{
    tipo_pago_id: number;
    origen: "REGULAR" | "ADICIONAL";
    observaciones?: string | null;
  }>
) {
  assertDistinctDetalles(inputDetalles);

  await assertTransactionPlanOrThrow(conn, transactionPlanId);

  const transactionRule = await getPlanRule(conn, transactionPlanId);

  const detalles: any[] = [];

  for (const input of inputDetalles) {
    const tipoPagoId = Number(input.tipo_pago_id);
    const origen = input.origen ?? "REGULAR";

    const config = await getJugadorTipoPagoConfig(conn, academiaId, jugadorId, tipoPagoId, fechaPago);

    let tarifaId: number;
    let montoBase: number;

    if (config) {
      /*
       * Cobro regular o adicional de un concepto
       * que ya forma parte de la configuración del jugador.
       */
      tarifaId = config.tarifa_id;
      montoBase = config.monto_asignado;
    } else {
      if (origen === "REGULAR") {
        businessError(`El jugador no posee una configuración financiera vigente para el tipo de pago ${tipoPagoId}`);
      }

      /*
       * Concepto extraordinario:
       * puede usar la tarifa vigente de academia.
       */
      const tarifa = await getTarifaActualOrThrow(conn, academiaId, tipoPagoId);

      tarifaId = tarifa.tarifa_id;
      montoBase = tarifa.monto;
    }

    /*
     * El descuento de inscripción ya está incorporado
     * dentro de montoBase.
     *
     * Aquí solo calculamos el beneficio EXTRA
     * de esta transacción.
     */
    const calculated = calculateBenefit(montoBase, transactionRule);

    detalles.push({
      tipo_pago_id: tipoPagoId,
      tarifa_id: tarifaId,

      /*
       * plan_regla_id representa exclusivamente
       * la regla adicional de esta transacción.
       */
      plan_regla_id: calculated.plan_regla_id,

      monto_base: calculated.monto_base,
      monto_descuento: calculated.monto_descuento,
      monto_total: calculated.monto_total,

      origen,

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

        j.rut_jugador AS jugador_rut,
        j.nombre_jugador AS jugador_nombre,
        j.categoria_id,

        c.nombre AS categoria_nombre,

        sr.nombre AS sucursal_nombre,

        pc.nombre AS plan_nombre,

        sp.nombre AS situacion_pago_nombre,

        mp.nombre AS medio_pago_nombre

      FROM pagos_jugador p

      INNER JOIN jugadores j
        ON j.id = p.jugador_id
       AND j.academia_id = p.academia_id

      LEFT JOIN categorias c
        ON c.id = j.categoria_id
       AND c.academia_id = p.academia_id

      LEFT JOIN sucursales_real sr
        ON sr.id = p.sucursal_id
       AND sr.academia_id = p.academia_id

      LEFT JOIN planes_catalogo pc
        ON pc.id = p.plan_catalogo_id

      LEFT JOIN situacion_pago sp
        ON sp.id = p.situacion_pago_id

      LEFT JOIN medio_pago mp
        ON mp.id = p.medio_pago_id

      WHERE p.id = ?
        AND p.academia_id = ?

      LIMIT 1
    `,
    [pagoId, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

/* =========================================================
   DETALLES DE PAGO
========================================================= */

async function getPagoDetalles(conn: any, pagoId: number) {
  const [rows]: any = await conn.query(
    `
      SELECT
        pd.id,
        pd.pago_id,
        pd.tipo_pago_id,

        tp.nombre AS tipo_pago_nombre,

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
        pr.valor AS beneficio_valor

      FROM pago_detalle pd

      INNER JOIN tipo_pago tp
        ON tp.id = pd.tipo_pago_id

      LEFT JOIN plan_reglas pr
        ON pr.id = pd.plan_regla_id

      WHERE pd.pago_id = ?

      ORDER BY pd.id ASC
    `,
    [pagoId]
  );

  return rows ?? [];
}

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

        tp.nombre AS tipo_pago_nombre,

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
        pr.valor AS beneficio_valor

      FROM pago_detalle pd

      INNER JOIN tipo_pago tp
        ON tp.id = pd.tipo_pago_id

      LEFT JOIN plan_reglas pr
        ON pr.id = pd.plan_regla_id

      WHERE pd.pago_id IN (${placeholders})

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

    j.rut_jugador AS jugador_rut,
    j.nombre_jugador AS jugador_nombre,
    j.categoria_id,

    c.nombre AS categoria_nombre,

    sr.nombre AS sucursal_nombre,

    pc.nombre AS plan_nombre,

    sp.nombre AS situacion_pago_nombre,

    mp.nombre AS medio_pago_nombre

  FROM pagos_jugador p

  INNER JOIN jugadores j
    ON j.id = p.jugador_id
   AND j.academia_id = p.academia_id

  LEFT JOIN categorias c
    ON c.id = j.categoria_id
   AND c.academia_id = p.academia_id

  LEFT JOIN sucursales_real sr
    ON sr.id = p.sucursal_id
   AND sr.academia_id = p.academia_id

  LEFT JOIN planes_catalogo pc
    ON pc.id = p.plan_catalogo_id

  LEFT JOIN situacion_pago sp
    ON sp.id = p.situacion_pago_id

  LEFT JOIN medio_pago mp
    ON mp.id = p.medio_pago_id
`;

/* =========================================================
   ROUTER
========================================================= */

export default async function pagos_jugador(app: FastifyInstance) {
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
            WHERE p.academia_id = ?
          `;

        const params: any[] = [academia_id];

        if (jugador_rut) {
          sql += ` AND j.rut_jugador = ?`;
          params.push(jugador_rut);
        }

        if (jugador_id) {
          sql += ` AND p.jugador_id = ?`;
          params.push(jugador_id);
        }

        if (sucursal_id) {
          sql += ` AND p.sucursal_id = ?`;
          params.push(sucursal_id);
        }

        if (plan_catalogo_id) {
          sql += ` AND p.plan_catalogo_id = ?`;
          params.push(plan_catalogo_id);
        }

        if (situacion_pago_id) {
          sql += ` AND p.situacion_pago_id = ?`;
          params.push(situacion_pago_id);
        }

        if (tipo_pago_id) {
          sql += `
            AND EXISTS (
              SELECT 1
              FROM pago_detalle pd_filter
              WHERE pd_filter.pago_id = p.id
                AND pd_filter.tipo_pago_id = ?
            )
          `;
          params.push(tipo_pago_id);
        }

        if (year) {
          sql += ` AND YEAR(p.fecha_pago) = ?`;
          params.push(year);
        }

        if (month) {
          sql += ` AND MONTH(p.fecha_pago) = ?`;
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
              WHERE p.academia_id = ?

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

        await getJugadorByRutOrThrow(db, academia_id, parsed.data.jugador_rut);

        const [rows]: any = await db.query(
          PAYMENT_SELECT +
            `
              WHERE p.academia_id = ?
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

          message:
            err?.message === "FORBIDDEN_JUGADOR"
              ? "FORBIDDEN_JUGADOR"
              : err?.statusCode
                ? err.message
                : "Error al listar pagos por jugador",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     GET /configuracion/jugador/:jugador_rut
     BASES FINANCIERAS ACTUALES DEL JUGADOR
  ======================================================= */

  app.get(
    "/configuracion/jugador/:jugador_rut",
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

        const jugador = await getJugadorByRutOrThrow(db, academia_id, parsed.data.jugador_rut);

        const [rows]: any = await db.query(
          `
            SELECT
              jpc.id AS jugador_plan_catalogo_id,
              jpc.jugador_id,
              jpc.tipo_pago_id,

              tp.nombre AS tipo_pago_nombre,

              jpc.plan_id,
              pc.nombre AS plan_nombre,

              jpc.tarifa_id,
              jpc.monto_tarifa,
              jpc.monto_asignado,

              (
                jpc.monto_tarifa -
                jpc.monto_asignado
              ) AS descuento_inicial,

              jpc.fecha_inicio,
              jpc.fecha_fin,
              jpc.estado_id

            FROM jugador_plan_catalogo jpc

            INNER JOIN tipo_pago tp
              ON tp.id = jpc.tipo_pago_id

            INNER JOIN planes_catalogo pc
              ON pc.id = jpc.plan_id

            WHERE jpc.academia_id = ?
              AND jpc.jugador_id = ?
              AND jpc.estado_id = 1

              AND jpc.fecha_inicio <= CURDATE()

              AND (
                jpc.fecha_fin IS NULL
                OR jpc.fecha_fin >= CURDATE()
              )

            ORDER BY
              tp.nombre ASC,
              jpc.id ASC
          `,
          [academia_id, Number(jugador.id)]
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,
          academia_id,
          jugador: {
            id: Number(jugador.id),
            rut_jugador: Number(jugador.rut_jugador),
            nombre_jugador: String(jugador.nombre_jugador ?? ""),
          },
          count: rows?.length ?? 0,
          items: rows ?? [],
        });
      } catch (err: any) {
        const code = getStatusCode(err);

        reply.header("Cache-Control", "no-store");

        return reply.code(code).send({
          ok: false,

          message:
            err?.message === "FORBIDDEN_JUGADOR"
              ? "FORBIDDEN_JUGADOR"
              : err?.statusCode
                ? err.message
                : "Error al obtener configuración financiera del jugador",

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
          message: err?.statusCode ? err.message : "Error al obtener pago",
          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     POST /
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

        const jugador = await getJugadorOrThrow(conn, academia_id, data.jugador_id);

        await assertSucursalOrThrow(conn, academia_id, data.jugador_id, data.sucursal_id);

        await assertSituacionPagoOrThrow(conn, data.situacion_pago_id);

        await assertMedioPagoOrThrow(conn, data.medio_pago_id);

        /*
         * La base ya NO proviene directamente
         * de tarifas_academia.
         *
         * buildDetalles obtiene monto_asignado
         * del jugador.
         */
        const detalles = await buildDetalles(
          conn,
          academia_id,
          data.jugador_id,
          fechaPago,
          data.plan_catalogo_id,
          data.detalles
        );

        const totals = calculateTotals(detalles);

        const firstDetail = detalles[0];

        if (!firstDetail) {
          businessError("El pago no contiene detalles válidos");
        }

        const result: any = await insertPagoHeaderCompat(conn, {
          academia_id,
          jugador_id: data.jugador_id,
          jugador_rut: Number(jugador.rut_jugador),
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
          tipo_pago_id: Number(firstDetail.tipo_pago_id),
        });

        const pagoId = Number(result?.insertId);

        if (!Number.isInteger(pagoId) || pagoId <= 0) {
          throw new Error("No fue posible obtener el ID del pago creado");
        }

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

        console.error("[pagos_jugador] POST /", {
          message: err?.message,
          code: err?.code,
          errno: err?.errno,
          sqlMessage: err?.sqlMessage,
          sql: err?.sql,
          statusCode: err?.statusCode,
        });

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

          detail: err?.sqlMessage ?? err?.message,
        });
      } finally {
        conn.release();
      }
    }
  );

  /* =======================================================
     PUT /:id
     ACTUALIZACIÓN PARCIAL
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
          businessError("Pago no encontrado", 404);
        }

        const body = parsed.data;

        const jugadorId = body.jugador_id ?? Number(current.jugador_id);

        const sucursalId =
          body.sucursal_id !== undefined
            ? body.sucursal_id
            : current.sucursal_id == null
              ? null
              : Number(current.sucursal_id);

        const transactionPlanId =
          body.plan_catalogo_id !== undefined
            ? body.plan_catalogo_id
            : current.plan_catalogo_id == null
              ? null
              : Number(current.plan_catalogo_id);

        const situacionPagoId = body.situacion_pago_id ?? Number(current.situacion_pago_id);

        const medioPagoId = body.medio_pago_id ?? Number(current.medio_pago_id);

        const fechaPago =
          body.fecha_pago !== undefined ? toSQLDate(body.fecha_pago) : normalizeSQLDate(current.fecha_pago);

        if (!fechaPago) {
          businessError("fecha_pago inválida");
        }

        const jugador = await getJugadorOrThrow(conn, academia_id, jugadorId);

        await assertSucursalOrThrow(conn, academia_id, jugadorId, sucursalId);

        await assertSituacionPagoOrThrow(conn, situacionPagoId);

        await assertMedioPagoOrThrow(conn, medioPagoId);

        /*
         * Si no recalculamos, preservamos
         * el snapshot histórico existente.
         */
        let montoBase = Number(current.monto_base);
        let montoDescuento = Number(current.monto_descuento);
        let montoTotal = Number(current.monto_total);

        /*
         * Debemos recalcular cuando cambia algo
         * que pueda alterar la configuración financiera:
         *
         * - detalles
         * - beneficio adicional
         * - jugador
         * - fecha
         *
         * sucursal, medio, situación, observaciones
         * NO recalculan montos.
         */
        const recalculateDetalles =
          body.detalles !== undefined ||
          body.plan_catalogo_id !== undefined ||
          body.jugador_id !== undefined ||
          body.fecha_pago !== undefined;

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

          const nuevosDetalles = await buildDetalles(
            conn,
            academia_id,
            jugadorId,
            fechaPago,
            transactionPlanId,
            requestedDetalles
          );

          const totals = calculateTotals(nuevosDetalles);

          montoBase = totals.monto_base;
          montoDescuento = totals.monto_descuento;
          montoTotal = totals.monto_total;

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

        const currentDetallesForLegacy = await getPagoDetalles(conn, id);

        const legacyTipoPagoId = Number(currentDetallesForLegacy?.[0]?.tipo_pago_id ?? 0);

        if (!Number.isInteger(legacyTipoPagoId) || legacyTipoPagoId <= 0) {
          businessError("El pago no posee un tipo de pago de referencia válido", 500);
        }

        const result: any = await updatePagoHeaderCompat(conn, id, academia_id, {
          jugador_id: jugadorId,
          jugador_rut: Number(jugador.rut_jugador),
          sucursal_id: sucursalId,
          plan_catalogo_id: transactionPlanId,
          situacion_pago_id: situacionPagoId,
          monto_base: montoBase,
          monto_descuento: montoDescuento,
          monto_total: montoTotal,
          fecha_pago: fechaPago,
          medio_pago_id: medioPagoId,
          comprobante_url:
            body.comprobante_url !== undefined ? cleanNullableString(body.comprobante_url) : current.comprobante_url,
          observaciones:
            body.observaciones !== undefined ? cleanNullableString(body.observaciones) : current.observaciones,
          tipo_pago_id: legacyTipoPagoId,
        });

        if (Number(result?.affectedRows ?? 0) === 0) {
          businessError("Pago no encontrado", 404);
        }

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

        console.error("[pagos_jugador] PUT /:id", {
          message: err?.message,
          code: err?.code,
          errno: err?.errno,
          sqlMessage: err?.sqlMessage,
          sql: err?.sql,
          statusCode: err?.statusCode,
        });

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

          detail: err?.sqlMessage ?? err?.message,
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

        await conn.beginTransaction();
        transactionStarted = true;

        const current = await getPagoHeader(conn, academia_id, pagoId);

        if (!current) {
          businessError("Pago no encontrado", 404);
        }

        /*
         * Eliminación explícita:
         * pago_detalle -> pagos_jugador
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
