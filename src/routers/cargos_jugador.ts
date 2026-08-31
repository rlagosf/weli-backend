// src/routers/cargos_jugador.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z, ZodError } from "zod";
import { db } from "../db";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * Tabla: cargos_jugador
 *
 * Campos:
 * - id
 * - academia_id
 * - sucursal_id
 * - jugador_id
 * - jugador_plan_id
 * - tarifa_id
 * - tipo_pago_id
 * - promocion_id
 * - periodo_desde
 * - periodo_hasta
 * - fecha_vencimiento
 * - monto_base
 * - monto_descuento
 * - monto_total
 * - situacion_pago_id
 * - created_at
 * - updated_at
 *
 * Scope:
 * - Multi-academia
 *
 * Seguridad:
 * - READ: roles 1, 2, 3
 * - WRITE: roles 1, 3
 *
 * Reglas:
 * - academia_id nunca se acepta desde el body.
 * - monto_total nunca se acepta desde el body.
 * - monto_total = monto_base - monto_descuento.
 * - todas las relaciones deben pertenecer a la academia efectiva.
 * - la tarifa debe corresponder al plan, tipo de pago y sucursal.
 * - promoción, si existe, debe aplicar al plan/sucursal/tipo de pago.
 * - un cargo con pagos asociados no se modifica ni elimina.
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

const CreateSchema = z
  .object({
    sucursal_id: z.coerce.number().int().positive(),
    jugador_id: z.coerce.number().int().positive(),
    jugador_plan_id: z.coerce.number().int().positive(),
    tarifa_id: z.coerce.number().int().positive(),
    tipo_pago_id: z.coerce.number().int().positive(),

    promocion_id: z.union([z.coerce.number().int().positive(), z.null()]).optional().default(null),

    periodo_desde: DateString,
    periodo_hasta: DateString,
    fecha_vencimiento: DateString,

    monto_base: z.coerce.number().finite().min(0),
    monto_descuento: z.coerce.number().finite().min(0).default(0),

    situacion_pago_id: z.coerce.number().int().positive(),
  })
  .strict();

const PutSchema = z
  .object({
    sucursal_id: z.coerce.number().int().positive(),
    jugador_id: z.coerce.number().int().positive(),
    jugador_plan_id: z.coerce.number().int().positive(),
    tarifa_id: z.coerce.number().int().positive(),
    tipo_pago_id: z.coerce.number().int().positive(),

    promocion_id: z.union([z.coerce.number().int().positive(), z.null()]),

    periodo_desde: DateString,
    periodo_hasta: DateString,
    fecha_vencimiento: DateString,

    monto_base: z.coerce.number().finite().min(0),
    monto_descuento: z.coerce.number().finite().min(0),

    situacion_pago_id: z.coerce.number().int().positive(),
  })
  .strict();

const PatchSchema = z
  .object({
    sucursal_id: z.coerce.number().int().positive().optional(),
    jugador_id: z.coerce.number().int().positive().optional(),
    jugador_plan_id: z.coerce.number().int().positive().optional(),
    tarifa_id: z.coerce.number().int().positive().optional(),
    tipo_pago_id: z.coerce.number().int().positive().optional(),

    promocion_id: z.union([z.coerce.number().int().positive(), z.null()]).optional(),

    periodo_desde: DateString.optional(),
    periodo_hasta: DateString.optional(),
    fecha_vencimiento: DateString.optional(),

    monto_base: z.coerce.number().finite().min(0).optional(),
    monto_descuento: z.coerce.number().finite().min(0).optional(),

    situacion_pago_id: z.coerce.number().int().positive().optional(),
  })
  .strict();

const QuerySchema = z
  .object({
    jugador_id: z.coerce.number().int().positive().optional(),
    sucursal_id: z.coerce.number().int().positive().optional(),
    tipo_pago_id: z.coerce.number().int().positive().optional(),
    situacion_pago_id: z.coerce.number().int().positive().optional(),
    desde: DateString.optional(),
    hasta: DateString.optional(),

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

function normalize(row: any) {
  return {
    id: Number(row.id),
    academia_id: Number(row.academia_id),
    sucursal_id: Number(row.sucursal_id),
    jugador_id: Number(row.jugador_id),
    jugador_plan_id: Number(row.jugador_plan_id),
    tarifa_id: Number(row.tarifa_id),
    tipo_pago_id: Number(row.tipo_pago_id),

    promocion_id: row.promocion_id == null ? null : Number(row.promocion_id),

    periodo_desde: row.periodo_desde ?? null,
    periodo_hasta: row.periodo_hasta ?? null,
    fecha_vencimiento: row.fecha_vencimiento ?? null,

    monto_base: Number(row.monto_base ?? 0),
    monto_descuento: Number(row.monto_descuento ?? 0),
    monto_total: Number(row.monto_total ?? 0),

    situacion_pago_id: Number(row.situacion_pago_id),

    jugador_nombre: row.jugador_nombre == null ? undefined : String(row.jugador_nombre),

    plan_nombre: row.plan_nombre == null ? undefined : String(row.plan_nombre),

    tarifa_nombre: row.tarifa_nombre == null ? undefined : String(row.tarifa_nombre),

    tipo_pago_nombre: row.tipo_pago_nombre == null ? undefined : String(row.tipo_pago_nombre),

    sucursal_nombre: row.sucursal_nombre == null ? undefined : String(row.sucursal_nombre),

    promocion_nombre: row.promocion_nombre == null ? null : String(row.promocion_nombre),

    situacion_pago_nombre: row.situacion_pago_nombre == null ? undefined : String(row.situacion_pago_nombre),

    created_at: row.created_at ?? null,
    updated_at: row.updated_at ?? null,
  };
}

function validateDates(periodoDesde: string, periodoHasta: string, fechaVencimiento: string) {
  const desde = new Date(`${periodoDesde}T00:00:00Z`);
  const hasta = new Date(`${periodoHasta}T00:00:00Z`);
  const vencimiento = new Date(`${fechaVencimiento}T00:00:00Z`);

  if (Number.isNaN(desde.getTime()) || Number.isNaN(hasta.getTime()) || Number.isNaN(vencimiento.getTime())) {
    throw new Error("Una o más fechas son inválidas");
  }

  if (hasta < desde) {
    throw new Error("periodo_hasta no puede ser anterior a periodo_desde");
  }
}

function calculateTotal(montoBase: number, montoDescuento: number) {
  const base = Number(montoBase);
  const descuento = Number(montoDescuento);

  if (!Number.isFinite(base) || base < 0) {
    throw new Error("monto_base inválido");
  }

  if (!Number.isFinite(descuento) || descuento < 0) {
    throw new Error("monto_descuento inválido");
  }

  if (descuento > base) {
    throw new Error("monto_descuento no puede superar monto_base");
  }

  return Number((base - descuento).toFixed(2));
}

async function getCargo(academiaId: number, id: number) {
  const [rows]: any = await db.query(
    `
    SELECT
      c.id,
      c.academia_id,
      c.sucursal_id,
      c.jugador_id,
      c.jugador_plan_id,
      c.tarifa_id,
      c.tipo_pago_id,
      c.promocion_id,
      c.periodo_desde,
      c.periodo_hasta,
      c.fecha_vencimiento,
      c.monto_base,
      c.monto_descuento,
      c.monto_total,
      c.situacion_pago_id,
      c.created_at,
      c.updated_at,

      j.nombre_jugador AS jugador_nombre,
      pa.nombre AS plan_nombre,
      pt.nombre AS tarifa_nombre,
      tp.nombre AS tipo_pago_nombre,
      sr.nombre AS sucursal_nombre,
      pr.nombre AS promocion_nombre,
      sp.nombre AS situacion_pago_nombre

    FROM cargos_jugador c

    INNER JOIN jugadores j
      ON j.id = c.jugador_id

    INNER JOIN jugador_plan jp
      ON jp.id = c.jugador_plan_id

    INNER JOIN planes_academia pa
      ON pa.id = jp.plan_id

    INNER JOIN plan_tarifas pt
      ON pt.id = c.tarifa_id

    INNER JOIN tipo_pago tp
      ON tp.id = c.tipo_pago_id

    INNER JOIN sucursales_real sr
      ON sr.id = c.sucursal_id

    LEFT JOIN promociones_academia pr
      ON pr.id = c.promocion_id

    INNER JOIN situacion_pago sp
      ON sp.id = c.situacion_pago_id

    WHERE c.id = ?
      AND c.academia_id = ?

    LIMIT 1
    `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

async function hasPayments(academiaId: number, cargoId: number) {
  const [rows]: any = await db.query(
    `
    SELECT id
    FROM pagos_jugador
    WHERE academia_id = ?
      AND cargo_id = ?
    LIMIT 1
    `,
    [academiaId, cargoId]
  );

  return Array.isArray(rows) && rows.length > 0;
}

/**
 * Valida la integridad multi-tenant y comercial
 * del cargo antes de INSERT/UPDATE.
 */
async function validateRelations(
  academiaId: number,
  data: {
    sucursal_id: number;
    jugador_id: number;
    jugador_plan_id: number;
    tarifa_id: number;
    tipo_pago_id: number;
    promocion_id: number | null;
    periodo_desde: string;
    situacion_pago_id: number;
  }
) {
  /*
   * Jugador + plan del jugador + tarifa + sucursal +
   * asociación tarifa/sucursal + tipo de pago.
   */
  const [rows]: any = await db.query(
    `
    SELECT
      j.id AS jugador_id,
      jp.id AS jugador_plan_id,
      jp.plan_id AS plan_id,

      pt.id AS tarifa_id,
      pt.plan_id AS tarifa_plan_id,
      pt.tipo_pago_id AS tarifa_tipo_pago_id,

      sr.id AS sucursal_id,

      ts.id AS tarifa_sucursal_id,

      tp.id AS tipo_pago_id,

      sp.id AS situacion_pago_id

    FROM jugador_plan jp

    INNER JOIN jugadores j
      ON j.id = jp.jugador_id
     AND j.academia_id = ?

    INNER JOIN plan_tarifas pt
      ON pt.id = ?
     AND pt.academia_id = ?

    INNER JOIN sucursales_real sr
      ON sr.id = ?
     AND sr.academia_id = ?

    INNER JOIN tarifa_sucursal ts
      ON ts.tarifa_id = pt.id
     AND ts.sucursal_id = sr.id
     AND ts.academia_id = ?

    INNER JOIN tipo_pago tp
      ON tp.id = ?

    INNER JOIN situacion_pago sp
      ON sp.id = ?

    WHERE jp.id = ?
      AND jp.academia_id = ?
      AND jp.jugador_id = ?

      AND pt.plan_id = jp.plan_id
      AND pt.tipo_pago_id = ?

      AND pt.vigencia_desde <= ?
      AND (
        pt.vigencia_hasta IS NULL
        OR pt.vigencia_hasta >= ?
      )

    LIMIT 1
    `,
    [
      academiaId,

      data.tarifa_id,
      academiaId,

      data.sucursal_id,
      academiaId,

      academiaId,

      data.tipo_pago_id,
      data.situacion_pago_id,

      data.jugador_plan_id,
      academiaId,
      data.jugador_id,

      data.tipo_pago_id,

      data.periodo_desde,
      data.periodo_desde,
    ]
  );

  if (!rows?.length) {
    throw new Error(
      "Las relaciones del cargo son inválidas, no pertenecen a la academia o la tarifa no aplica al plan/sucursal/tipo de pago indicado"
    );
  }

  /*
   * tipo_pago puede ser histórico/global (academia_id NULL)
   * o tenantizado.
   */
  const [tipoRows]: any = await db.query(
    `
    SELECT id
    FROM tipo_pago
    WHERE id = ?
      AND (
        academia_id IS NULL
        OR academia_id = ?
      )
    LIMIT 1
    `,
    [data.tipo_pago_id, academiaId]
  );

  if (!tipoRows?.length) {
    throw new Error("El tipo de pago no pertenece a la academia");
  }

  /*
   * Promoción opcional.
   */
  if (data.promocion_id != null) {
    const [promoRows]: any = await db.query(
      `
      SELECT p.id

      FROM promociones_academia p

      INNER JOIN promocion_plan pp
        ON pp.promocion_id = p.id
       AND pp.academia_id = ?
       AND pp.plan_id = ?

      INNER JOIN promocion_sucursal ps
        ON ps.promocion_id = p.id
       AND ps.academia_id = ?
       AND ps.sucursal_id = ?

      INNER JOIN promocion_tipo_pago ptp
        ON ptp.promocion_id = p.id
       AND ptp.academia_id = ?
       AND ptp.tipo_pago_id = ?

      WHERE p.id = ?
        AND p.academia_id = ?
        AND p.estado_id = 1

        AND p.fecha_desde <= ?
        AND (
          p.fecha_hasta IS NULL
          OR p.fecha_hasta >= ?
        )

      LIMIT 1
      `,
      [
        academiaId,
        Number(rows[0].plan_id),

        academiaId,
        data.sucursal_id,

        academiaId,
        data.tipo_pago_id,

        data.promocion_id,
        academiaId,

        data.periodo_desde,
        data.periodo_desde,
      ]
    );

    if (!promoRows?.length) {
      throw new Error("La promoción no es válida para el plan, sucursal, tipo de pago o período indicado");
    }
  }
}

function handleScopeError(reply: FastifyReply, err: any) {
  const status = Number(err?.statusCode ?? 0);

  if (status === 400 || status === 401 || status === 403) {
    reply.header("Cache-Control", "no-store");

    return reply.code(status).send({
      ok: false,
      message: err?.message ?? "No fue posible determinar la academia efectiva",
    });
  }

  return null;
}

/* =========================================================
   Router
========================================================= */

export default async function cargos_jugador(app: FastifyInstance) {
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
        module: "cargos_jugador",
        status: "ready",
        academia_id: academiaId,
        timestamp: new Date().toISOString(),
      });
    } catch (err: any) {
      const handled = handleScopeError(reply, err);

      if (handled) {
        return handled;
      }

      reply.header("Cache-Control", "no-store");

      return reply.code(500).send({
        ok: false,
        message: "Error en módulo de cargos",
      });
    }
  });

  /* =======================================================
     GET /
  ======================================================= */

  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academiaId = resolveAcademiaId(req);

      const query = QuerySchema.parse(req.query);

      const where: string[] = ["c.academia_id = ?"];

      const values: any[] = [academiaId];

      if (query.jugador_id !== undefined) {
        where.push("c.jugador_id = ?");

        values.push(query.jugador_id);
      }

      if (query.sucursal_id !== undefined) {
        where.push("c.sucursal_id = ?");

        values.push(query.sucursal_id);
      }

      if (query.tipo_pago_id !== undefined) {
        where.push("c.tipo_pago_id = ?");

        values.push(query.tipo_pago_id);
      }

      if (query.situacion_pago_id !== undefined) {
        where.push("c.situacion_pago_id = ?");

        values.push(query.situacion_pago_id);
      }

      if (query.desde !== undefined) {
        where.push("c.fecha_vencimiento >= ?");

        values.push(query.desde);
      }

      if (query.hasta !== undefined) {
        where.push("c.fecha_vencimiento <= ?");

        values.push(query.hasta);
      }

      values.push(query.limit);

      const [rows]: any = await db.query(
        `
            SELECT
              c.id,
              c.academia_id,
              c.sucursal_id,
              c.jugador_id,
              c.jugador_plan_id,
              c.tarifa_id,
              c.tipo_pago_id,
              c.promocion_id,
              c.periodo_desde,
              c.periodo_hasta,
              c.fecha_vencimiento,
              c.monto_base,
              c.monto_descuento,
              c.monto_total,
              c.situacion_pago_id,
              c.created_at,
              c.updated_at,

              j.nombre_jugador AS jugador_nombre,
              pa.nombre AS plan_nombre,
              pt.nombre AS tarifa_nombre,
              tp.nombre AS tipo_pago_nombre,
              sr.nombre AS sucursal_nombre,
              pr.nombre AS promocion_nombre,
              sp.nombre AS situacion_pago_nombre

            FROM cargos_jugador c

            INNER JOIN jugadores j
              ON j.id = c.jugador_id

            INNER JOIN jugador_plan jp
              ON jp.id = c.jugador_plan_id

            INNER JOIN planes_academia pa
              ON pa.id = jp.plan_id

            INNER JOIN plan_tarifas pt
              ON pt.id = c.tarifa_id

            INNER JOIN tipo_pago tp
              ON tp.id = c.tipo_pago_id

            INNER JOIN sucursales_real sr
              ON sr.id = c.sucursal_id

            LEFT JOIN promociones_academia pr
              ON pr.id = c.promocion_id

            INNER JOIN situacion_pago sp
              ON sp.id = c.situacion_pago_id

            WHERE ${where.join(" AND ")}

            ORDER BY
              c.fecha_vencimiento DESC,
              c.id DESC

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

      if (handled) {
        return handled;
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al listar cargos",
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

      return reply.code(400).send({
        ok: false,
        message: "ID inválido",
      });
    }

    try {
      const academiaId = resolveAcademiaId(req);

      const row = await getCargo(academiaId, parsed.data.id);

      reply.header("Cache-Control", "no-store");

      if (!row) {
        return reply.code(404).send({
          ok: false,
          message: "Cargo no encontrado",
        });
      }

      return reply.send({
        ok: true,
        item: normalize(row),
      });
    } catch (err: any) {
      const handled = handleScopeError(reply, err);

      if (handled) {
        return handled;
      }

      reply.header("Cache-Control", "no-store");

      return reply.code(500).send({
        ok: false,
        message: "Error al obtener cargo",
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

      validateDates(body.periodo_desde, body.periodo_hasta, body.fecha_vencimiento);

      const montoTotal = calculateTotal(body.monto_base, body.monto_descuento);

      await validateRelations(academiaId, {
        sucursal_id: body.sucursal_id,

        jugador_id: body.jugador_id,

        jugador_plan_id: body.jugador_plan_id,

        tarifa_id: body.tarifa_id,

        tipo_pago_id: body.tipo_pago_id,

        promocion_id: body.promocion_id,

        periodo_desde: body.periodo_desde,

        situacion_pago_id: body.situacion_pago_id,
      });

      const [result]: any = await db.query(
        `
            INSERT INTO cargos_jugador
            (
              academia_id,
              sucursal_id,
              jugador_id,
              jugador_plan_id,
              tarifa_id,
              tipo_pago_id,
              promocion_id,
              periodo_desde,
              periodo_hasta,
              fecha_vencimiento,
              monto_base,
              monto_descuento,
              monto_total,
              situacion_pago_id
            )
            VALUES (
              ?, ?, ?, ?, ?, ?, ?,
              ?, ?, ?,
              ?, ?, ?, ?
            )
            `,
        [
          academiaId,

          body.sucursal_id,
          body.jugador_id,
          body.jugador_plan_id,
          body.tarifa_id,
          body.tipo_pago_id,
          body.promocion_id,

          body.periodo_desde,
          body.periodo_hasta,
          body.fecha_vencimiento,

          body.monto_base,
          body.monto_descuento,
          montoTotal,

          body.situacion_pago_id,
        ]
      );

      const insertId = Number(result?.insertId);

      const row = await getCargo(academiaId, insertId);

      reply.header("Cache-Control", "no-store");

      return reply.code(201).send({
        ok: true,
        id: insertId,
        item: row
          ? normalize(row)
          : {
              id: insertId,
              academia_id: academiaId,
              monto_total: montoTotal,
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

      if (handled) {
        return handled;
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({
          ok: false,
          message: "Ya existe un cargo para este jugador, tarifa y período",
        });
      }

      if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
        return reply.code(409).send({
          ok: false,
          message: "Uno o más datos relacionados no existen",
        });
      }

      if (
        [
          "Una o más fechas son inválidas",
          "periodo_hasta no puede ser anterior a periodo_desde",
          "monto_base inválido",
          "monto_descuento inválido",
          "monto_descuento no puede superar monto_base",
        ].includes(String(err?.message ?? "")) ||
        String(err?.message ?? "").startsWith("Las relaciones del cargo") ||
        String(err?.message ?? "").startsWith("La promoción") ||
        String(err?.message ?? "").startsWith("El tipo de pago")
      ) {
        return reply.code(400).send({
          ok: false,
          message: err.message,
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al crear cargo",
      });
    }
  });

  /* =======================================================
     PUT /:id
  ======================================================= */

  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsedId = IdParam.safeParse(req.params);

    if (!parsedId.success) {
      reply.header("Cache-Control", "no-store");

      return reply.code(400).send({
        ok: false,
        message: "ID inválido",
      });
    }

    try {
      const academiaId = resolveAcademiaId(req);

      const id = parsedId.data.id;

      const current = await getCargo(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Cargo no encontrado",
        });
      }

      if (await hasPayments(academiaId, id)) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "El cargo posee pagos asociados y no puede modificarse",
        });
      }

      const body = PutSchema.parse(req.body);

      validateDates(body.periodo_desde, body.periodo_hasta, body.fecha_vencimiento);

      const montoTotal = calculateTotal(body.monto_base, body.monto_descuento);

      await validateRelations(academiaId, {
        sucursal_id: body.sucursal_id,

        jugador_id: body.jugador_id,

        jugador_plan_id: body.jugador_plan_id,

        tarifa_id: body.tarifa_id,

        tipo_pago_id: body.tipo_pago_id,

        promocion_id: body.promocion_id,

        periodo_desde: body.periodo_desde,

        situacion_pago_id: body.situacion_pago_id,
      });

      const [result]: any = await db.query(
        `
            UPDATE cargos_jugador
            SET
              sucursal_id = ?,
              jugador_id = ?,
              jugador_plan_id = ?,
              tarifa_id = ?,
              tipo_pago_id = ?,
              promocion_id = ?,
              periodo_desde = ?,
              periodo_hasta = ?,
              fecha_vencimiento = ?,
              monto_base = ?,
              monto_descuento = ?,
              monto_total = ?,
              situacion_pago_id = ?

            WHERE id = ?
              AND academia_id = ?

            LIMIT 1
            `,
        [
          body.sucursal_id,
          body.jugador_id,
          body.jugador_plan_id,
          body.tarifa_id,
          body.tipo_pago_id,
          body.promocion_id,
          body.periodo_desde,
          body.periodo_hasta,
          body.fecha_vencimiento,
          body.monto_base,
          body.monto_descuento,
          montoTotal,
          body.situacion_pago_id,

          id,
          academiaId,
        ]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Cargo no encontrado",
        });
      }

      const updated = await getCargo(academiaId, id);

      return reply.send({
        ok: true,
        updated: updated
          ? normalize(updated)
          : {
              id,
              academia_id: academiaId,
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

      if (handled) {
        return handled;
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({
          ok: false,
          message: "Ya existe un cargo para este jugador, tarifa y período",
        });
      }

      if (
        String(err?.message ?? "").startsWith("Las relaciones") ||
        String(err?.message ?? "").startsWith("La promoción") ||
        String(err?.message ?? "").startsWith("El tipo de pago") ||
        String(err?.message ?? "").includes("monto_") ||
        String(err?.message ?? "").includes("periodo_")
      ) {
        return reply.code(400).send({
          ok: false,
          message: err.message,
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar cargo",
      });
    }
  });

  /* =======================================================
     PATCH /:id
  ======================================================= */

  app.patch("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsedId = IdParam.safeParse(req.params);

    if (!parsedId.success) {
      reply.header("Cache-Control", "no-store");

      return reply.code(400).send({
        ok: false,
        message: "ID inválido",
      });
    }

    try {
      const academiaId = resolveAcademiaId(req);

      const id = parsedId.data.id;

      const current = await getCargo(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Cargo no encontrado",
        });
      }

      if (await hasPayments(academiaId, id)) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "El cargo posee pagos asociados y no puede modificarse",
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

      /*
       * Creamos el estado final del cargo para
       * validar la relación completa antes del UPDATE.
       */
      const merged = {
        sucursal_id: body.sucursal_id ?? Number(current.sucursal_id),

        jugador_id: body.jugador_id ?? Number(current.jugador_id),

        jugador_plan_id: body.jugador_plan_id ?? Number(current.jugador_plan_id),

        tarifa_id: body.tarifa_id ?? Number(current.tarifa_id),

        tipo_pago_id: body.tipo_pago_id ?? Number(current.tipo_pago_id),

        promocion_id:
          body.promocion_id !== undefined
            ? body.promocion_id
            : current.promocion_id == null
              ? null
              : Number(current.promocion_id),

        periodo_desde: body.periodo_desde ?? String(current.periodo_desde).slice(0, 10),

        periodo_hasta: body.periodo_hasta ?? String(current.periodo_hasta).slice(0, 10),

        fecha_vencimiento: body.fecha_vencimiento ?? String(current.fecha_vencimiento).slice(0, 10),

        monto_base: body.monto_base ?? Number(current.monto_base),

        monto_descuento: body.monto_descuento ?? Number(current.monto_descuento),

        situacion_pago_id: body.situacion_pago_id ?? Number(current.situacion_pago_id),
      };

      validateDates(merged.periodo_desde, merged.periodo_hasta, merged.fecha_vencimiento);

      const montoTotal = calculateTotal(merged.monto_base, merged.monto_descuento);

      await validateRelations(academiaId, {
        sucursal_id: merged.sucursal_id,

        jugador_id: merged.jugador_id,

        jugador_plan_id: merged.jugador_plan_id,

        tarifa_id: merged.tarifa_id,

        tipo_pago_id: merged.tipo_pago_id,

        promocion_id: merged.promocion_id,

        periodo_desde: merged.periodo_desde,

        situacion_pago_id: merged.situacion_pago_id,
      });

      const [result]: any = await db.query(
        `
            UPDATE cargos_jugador
            SET
              sucursal_id = ?,
              jugador_id = ?,
              jugador_plan_id = ?,
              tarifa_id = ?,
              tipo_pago_id = ?,
              promocion_id = ?,
              periodo_desde = ?,
              periodo_hasta = ?,
              fecha_vencimiento = ?,
              monto_base = ?,
              monto_descuento = ?,
              monto_total = ?,
              situacion_pago_id = ?

            WHERE id = ?
              AND academia_id = ?

            LIMIT 1
            `,
        [
          merged.sucursal_id,
          merged.jugador_id,
          merged.jugador_plan_id,
          merged.tarifa_id,
          merged.tipo_pago_id,
          merged.promocion_id,
          merged.periodo_desde,
          merged.periodo_hasta,
          merged.fecha_vencimiento,
          merged.monto_base,
          merged.monto_descuento,
          montoTotal,
          merged.situacion_pago_id,

          id,
          academiaId,
        ]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Cargo no encontrado",
        });
      }

      const updated = await getCargo(academiaId, id);

      return reply.send({
        ok: true,
        updated: updated
          ? normalize(updated)
          : {
              id,
              academia_id: academiaId,
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

      if (handled) {
        return handled;
      }

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({
          ok: false,
          message: "Ya existe un cargo para este jugador, tarifa y período",
        });
      }

      if (
        String(err?.message ?? "").startsWith("Las relaciones") ||
        String(err?.message ?? "").startsWith("La promoción") ||
        String(err?.message ?? "").startsWith("El tipo de pago") ||
        String(err?.message ?? "").includes("monto_") ||
        String(err?.message ?? "").includes("periodo_")
      ) {
        return reply.code(400).send({
          ok: false,
          message: err.message,
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar cargo",
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

      return reply.code(400).send({
        ok: false,
        message: "ID inválido",
      });
    }

    try {
      const academiaId = resolveAcademiaId(req);

      const id = parsed.data.id;

      const current = await getCargo(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Cargo no encontrado",
        });
      }

      if (await hasPayments(academiaId, id)) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "El cargo posee pagos asociados y no puede eliminarse",
        });
      }

      const [result]: any = await db.query(
        `
            DELETE FROM cargos_jugador
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
          message: "Cargo no encontrado",
        });
      }

      return reply.send({
        ok: true,
        deleted: id,
      });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      const handled = handleScopeError(reply, err);

      if (handled) {
        return handled;
      }

      if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar el cargo porque está en uso",
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar cargo",
      });
    }
  });
}
