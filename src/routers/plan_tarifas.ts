// src/routers/plan_tarifas.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * Tabla: plan_tarifas
 *
 * Campos:
 * - id
 * - academia_id
 * - plan_id
 * - tipo_pago_id
 * - nombre
 * - monto
 * - vigencia_desde
 * - vigencia_hasta
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
 * - academia_id nunca se recibe desde body.
 * - plan_id debe pertenecer a la academia efectiva.
 * - tipo_pago_id debe ser global (academia_id NULL) o pertenecer a la academia efectiva.
 * - monto debe ser >= 0.
 * - vigencia_hasta >= vigencia_desde cuando exista.
 * - una tarifa utilizada por cargos conserva sus datos históricos.
 * - modificar precios históricos requiere crear una nueva tarifa/version.
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
    plan_id: z.coerce.number().int().positive(),
    tipo_pago_id: z.coerce.number().int().positive(),

    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(120),

    monto: z.coerce.number().finite().min(0).max(99999999.99),

    vigencia_desde: DateString,
    vigencia_hasta: z.union([DateString, z.null()]).optional().default(null),

    estado_id: z.coerce.number().int().positive().max(255).default(1),
  })
  .strict();

const PutSchema = z
  .object({
    plan_id: z.coerce.number().int().positive(),
    tipo_pago_id: z.coerce.number().int().positive(),

    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(120),

    monto: z.coerce.number().finite().min(0).max(99999999.99),

    vigencia_desde: DateString,
    vigencia_hasta: z.union([DateString, z.null()]),

    estado_id: z.coerce.number().int().positive().max(255),
  })
  .strict();

const PatchSchema = z
  .object({
    plan_id: z.coerce.number().int().positive().optional(),
    tipo_pago_id: z.coerce.number().int().positive().optional(),

    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(120).optional(),

    monto: z.coerce.number().finite().min(0).max(99999999.99).optional(),

    vigencia_desde: DateString.optional(),
    vigencia_hasta: z.union([DateString, z.null()]).optional(),

    estado_id: z.coerce.number().int().positive().max(255).optional(),
  })
  .strict();

const QuerySchema = z
  .object({
    plan_id: z.coerce.number().int().positive().optional(),
    tipo_pago_id: z.coerce.number().int().positive().optional(),
    estado_id: z.coerce.number().int().positive().max(255).optional(),

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

function normalize(row: any) {
  return {
    id: Number(row.id),
    academia_id: Number(row.academia_id),

    plan_id: Number(row.plan_id),
    tipo_pago_id: Number(row.tipo_pago_id),

    nombre: String(row.nombre ?? ""),
    monto: Number(row.monto ?? 0),

    vigencia_desde: row.vigencia_desde ?? null,
    vigencia_hasta: row.vigencia_hasta ?? null,

    estado_id: Number(row.estado_id),

    plan_nombre: row.plan_nombre == null ? undefined : String(row.plan_nombre),
    tipo_pago_nombre: row.tipo_pago_nombre == null ? undefined : String(row.tipo_pago_nombre),

    created_at: row.created_at ?? null,
    updated_at: row.updated_at ?? null,
  };
}

function dbDate(value: any): string | null {
  if (value == null) return null;

  if (value instanceof Date) {
    return value.toISOString().slice(0, 10);
  }

  return String(value).slice(0, 10);
}

function validateDates(vigenciaDesde: string, vigenciaHasta: string | null) {
  const desde = new Date(`${vigenciaDesde}T00:00:00Z`);

  if (Number.isNaN(desde.getTime())) {
    throw new Error("vigencia_desde inválida");
  }

  if (vigenciaHasta !== null) {
    const hasta = new Date(`${vigenciaHasta}T00:00:00Z`);

    if (Number.isNaN(hasta.getTime())) {
      throw new Error("vigencia_hasta inválida");
    }

    if (hasta < desde) {
      throw new Error("vigencia_hasta no puede ser anterior a vigencia_desde");
    }
  }
}

function normalizeMoney(value: number) {
  const monto = Number(value);

  if (!Number.isFinite(monto) || monto < 0 || monto > 99999999.99) {
    throw new Error("Monto inválido");
  }

  return Number(monto.toFixed(2));
}

async function getTarifa(academiaId: number, id: number) {
  const [rows]: any = await db.query(
    `
    SELECT
      pt.id,
      pt.academia_id,
      pt.plan_id,
      pt.tipo_pago_id,
      pt.nombre,
      pt.monto,
      pt.vigencia_desde,
      pt.vigencia_hasta,
      pt.estado_id,
      pt.created_at,
      pt.updated_at,

      pa.nombre AS plan_nombre,
      tp.nombre AS tipo_pago_nombre

    FROM plan_tarifas pt

    INNER JOIN planes_academia pa
      ON pa.id = pt.plan_id
     AND pa.academia_id = pt.academia_id

    INNER JOIN tipo_pago tp
      ON tp.id = pt.tipo_pago_id

    WHERE pt.id = ?
      AND pt.academia_id = ?

    LIMIT 1
    `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

async function validatePlan(academiaId: number, planId: number, requireActive = true) {
  const [rows]: any = await db.query(
    `
    SELECT id, estado_id
    FROM planes_academia
    WHERE id = ?
      AND academia_id = ?
    LIMIT 1
    `,
    [planId, academiaId]
  );

  if (!rows?.length) {
    throw new Error("El plan no existe o no pertenece a la academia");
  }

  if (requireActive && Number(rows[0].estado_id) !== 1) {
    throw new Error("El plan seleccionado no se encuentra activo");
  }
}

async function validateTipoPago(academiaId: number, tipoPagoId: number) {
  const [rows]: any = await db.query(
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
    [tipoPagoId, academiaId]
  );

  if (!rows?.length) {
    throw new Error("El tipo de pago no existe o no pertenece a la academia");
  }
}

async function hasCargos(academiaId: number, tarifaId: number) {
  const [rows]: any = await db.query(
    `
    SELECT id
    FROM cargos_jugador
    WHERE academia_id = ?
      AND tarifa_id = ?
    LIMIT 1
    `,
    [academiaId, tarifaId]
  );

  return Array.isArray(rows) && rows.length > 0;
}

async function hasSucursalRelations(academiaId: number, tarifaId: number) {
  const [rows]: any = await db.query(
    `
    SELECT id
    FROM tarifa_sucursal
    WHERE academia_id = ?
      AND tarifa_id = ?
    LIMIT 1
    `,
    [academiaId, tarifaId]
  );

  return Array.isArray(rows) && rows.length > 0;
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
  return [
    "vigencia_desde inválida",
    "vigencia_hasta inválida",
    "vigencia_hasta no puede ser anterior a vigencia_desde",
    "Monto inválido",
    "El plan no existe o no pertenece a la academia",
    "El plan seleccionado no se encuentra activo",
    "El tipo de pago no existe o no pertenece a la academia",
  ].includes(String(err?.message ?? ""));
}

/* =========================================================
   Router
========================================================= */

export default async function plan_tarifas(app: FastifyInstance) {
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
        module: "plan_tarifas",
        status: "ready",
        academia_id: academiaId,
        timestamp: new Date().toISOString(),
      });
    } catch (err: any) {
      const handled = handleScopeError(reply, err);
      if (handled) return handled;

      reply.header("Cache-Control", "no-store");

      return reply.code(500).send({
        ok: false,
        message: "Error en módulo plan_tarifas",
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

      const where: string[] = ["pt.academia_id = ?"];
      const values: any[] = [academiaId];

      if (query.plan_id !== undefined) {
        where.push("pt.plan_id = ?");
        values.push(query.plan_id);
      }

      if (query.tipo_pago_id !== undefined) {
        where.push("pt.tipo_pago_id = ?");
        values.push(query.tipo_pago_id);
      }

      if (query.estado_id !== undefined) {
        where.push("pt.estado_id = ?");
        values.push(query.estado_id);
      }

      /*
       * Si se especifica fecha, esa fecha se utiliza
       * para determinar la vigencia.
       *
       * Si no se especifica, CURDATE().
       */
      const fechaReferencia = query.fecha ?? null;

      if (query.vigentes === "1") {
        if (fechaReferencia) {
          where.push("pt.vigencia_desde <= ?");
          where.push("(pt.vigencia_hasta IS NULL OR pt.vigencia_hasta >= ?)");
          values.push(fechaReferencia, fechaReferencia);
        } else {
          where.push("pt.vigencia_desde <= CURDATE()");
          where.push("(pt.vigencia_hasta IS NULL OR pt.vigencia_hasta >= CURDATE())");
        }
      }

      if (query.vigentes === "0") {
        if (fechaReferencia) {
          where.push("(pt.vigencia_desde > ? OR (pt.vigencia_hasta IS NOT NULL AND pt.vigencia_hasta < ?))");
          values.push(fechaReferencia, fechaReferencia);
        } else {
          where.push(
            "(pt.vigencia_desde > CURDATE() OR (pt.vigencia_hasta IS NOT NULL AND pt.vigencia_hasta < CURDATE()))"
          );
        }
      }

      values.push(query.limit);

      const [rows]: any = await db.query(
        `
        SELECT
          pt.id,
          pt.academia_id,
          pt.plan_id,
          pt.tipo_pago_id,
          pt.nombre,
          pt.monto,
          pt.vigencia_desde,
          pt.vigencia_hasta,
          pt.estado_id,
          pt.created_at,
          pt.updated_at,

          pa.nombre AS plan_nombre,
          tp.nombre AS tipo_pago_nombre

        FROM plan_tarifas pt

        INNER JOIN planes_academia pa
          ON pa.id = pt.plan_id
         AND pa.academia_id = pt.academia_id

        INNER JOIN tipo_pago tp
          ON tp.id = pt.tipo_pago_id

        WHERE ${where.join(" AND ")}

        ORDER BY
          pa.nombre ASC,
          tp.nombre ASC,
          pt.vigencia_desde DESC,
          pt.id DESC

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
        message: "Error al listar tarifas",
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
      const row = await getTarifa(academiaId, parsed.data.id);

      reply.header("Cache-Control", "no-store");

      if (!row) {
        return reply.code(404).send({
          ok: false,
          message: "Tarifa no encontrada",
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
        message: "Error al obtener tarifa",
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

      validateDates(body.vigencia_desde, body.vigencia_hasta);

      const monto = normalizeMoney(body.monto);

      await validatePlan(academiaId, body.plan_id, true);
      await validateTipoPago(academiaId, body.tipo_pago_id);

      const [result]: any = await db.query(
        `
        INSERT INTO plan_tarifas
          (
            academia_id,
            plan_id,
            tipo_pago_id,
            nombre,
            monto,
            vigencia_desde,
            vigencia_hasta,
            estado_id
          )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          academiaId,
          body.plan_id,
          body.tipo_pago_id,
          body.nombre.trim(),
          monto,
          body.vigencia_desde,
          body.vigencia_hasta,
          body.estado_id,
        ]
      );

      const insertId = Number(result?.insertId);
      const row = await getTarifa(academiaId, insertId);

      reply.header("Cache-Control", "no-store");

      return reply.code(201).send({
        ok: true,
        id: insertId,

        item: row
          ? normalize(row)
          : {
              id: insertId,
              academia_id: academiaId,
              plan_id: body.plan_id,
              tipo_pago_id: body.tipo_pago_id,
              nombre: body.nombre.trim(),
              monto,
              vigencia_desde: body.vigencia_desde,
              vigencia_hasta: body.vigencia_hasta,
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
          message: "La tarifa ya existe",
        });
      }

      if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
        return reply.code(409).send({
          ok: false,
          message: "El plan o tipo de pago indicado no existe",
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
        message: "Error al crear tarifa",
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

      const current = await getTarifa(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");
        return reply.code(404).send({ ok: false, message: "Tarifa no encontrada" });
      }

      const body = PutSchema.parse(req.body);

      validateDates(body.vigencia_desde, body.vigencia_hasta);

      const monto = normalizeMoney(body.monto);
      const currentMonto = Number(current.monto);
      const currentDesde = dbDate(current.vigencia_desde);

      const usedByCargos = await hasCargos(academiaId, id);
      const linkedToSucursal = await hasSucursalRelations(academiaId, id);

      /*
       * Integridad histórica.
       *
       * Una tarifa que ya produjo cargos no puede
       * cambiar sus datos económicos originales.
       */
      if (usedByCargos) {
        const immutableChanged =
          body.plan_id !== Number(current.plan_id) ||
          body.tipo_pago_id !== Number(current.tipo_pago_id) ||
          monto !== currentMonto ||
          body.vigencia_desde !== currentDesde;

        if (immutableChanged) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,
            message:
              "La tarifa posee cargos asociados. Para cambiar plan, tipo de pago, monto o vigencia inicial debe crear una nueva tarifa y cerrar la vigencia de la actual",
          });
        }
      }

      /*
       * Si ya está vinculada a sucursales, no permitimos
       * transformarla arbitrariamente en tarifa de otro plan.
       */
      if (linkedToSucursal && body.plan_id !== Number(current.plan_id)) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La tarifa está asociada a sucursales y no puede cambiar de plan",
        });
      }

      if (body.plan_id !== Number(current.plan_id)) {
        await validatePlan(academiaId, body.plan_id, true);
      } else {
        await validatePlan(academiaId, body.plan_id, false);
      }

      await validateTipoPago(academiaId, body.tipo_pago_id);

      const [result]: any = await db.query(
        `
        UPDATE plan_tarifas
        SET
          plan_id = ?,
          tipo_pago_id = ?,
          nombre = ?,
          monto = ?,
          vigencia_desde = ?,
          vigencia_hasta = ?,
          estado_id = ?
        WHERE id = ?
          AND academia_id = ?
        LIMIT 1
        `,
        [
          body.plan_id,
          body.tipo_pago_id,
          body.nombre.trim(),
          monto,
          body.vigencia_desde,
          body.vigencia_hasta,
          body.estado_id,
          id,
          academiaId,
        ]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Tarifa no encontrada",
        });
      }

      const updated = await getTarifa(academiaId, id);

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

      if (isBusinessValidationError(err)) {
        return reply.code(400).send({
          ok: false,
          message: err.message,
        });
      }

      if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
        return reply.code(409).send({
          ok: false,
          message: "El plan o tipo de pago indicado no existe",
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar tarifa",
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

      const current = await getTarifa(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");
        return reply.code(404).send({ ok: false, message: "Tarifa no encontrada" });
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
        plan_id: body.plan_id ?? Number(current.plan_id),
        tipo_pago_id: body.tipo_pago_id ?? Number(current.tipo_pago_id),
        nombre: body.nombre ?? String(current.nombre),
        monto: body.monto !== undefined ? normalizeMoney(body.monto) : Number(current.monto),
        vigencia_desde: body.vigencia_desde ?? dbDate(current.vigencia_desde)!,
        vigencia_hasta: body.vigencia_hasta !== undefined ? body.vigencia_hasta : dbDate(current.vigencia_hasta),
        estado_id: body.estado_id ?? Number(current.estado_id),
      };

      validateDates(merged.vigencia_desde, merged.vigencia_hasta);

      const usedByCargos = await hasCargos(academiaId, id);
      const linkedToSucursal = await hasSucursalRelations(academiaId, id);

      if (usedByCargos) {
        const immutableChanged =
          merged.plan_id !== Number(current.plan_id) ||
          merged.tipo_pago_id !== Number(current.tipo_pago_id) ||
          merged.monto !== Number(current.monto) ||
          merged.vigencia_desde !== dbDate(current.vigencia_desde);

        if (immutableChanged) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,
            message:
              "La tarifa posee cargos asociados. Para cambiar plan, tipo de pago, monto o vigencia inicial debe crear una nueva tarifa y cerrar la vigencia de la actual",
          });
        }
      }

      if (linkedToSucursal && merged.plan_id !== Number(current.plan_id)) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La tarifa está asociada a sucursales y no puede cambiar de plan",
        });
      }

      if (merged.plan_id !== Number(current.plan_id)) {
        await validatePlan(academiaId, merged.plan_id, true);
      } else {
        await validatePlan(academiaId, merged.plan_id, false);
      }

      await validateTipoPago(academiaId, merged.tipo_pago_id);

      const [result]: any = await db.query(
        `
        UPDATE plan_tarifas
        SET
          plan_id = ?,
          tipo_pago_id = ?,
          nombre = ?,
          monto = ?,
          vigencia_desde = ?,
          vigencia_hasta = ?,
          estado_id = ?
        WHERE id = ?
          AND academia_id = ?
        LIMIT 1
        `,
        [
          merged.plan_id,
          merged.tipo_pago_id,
          merged.nombre.trim(),
          merged.monto,
          merged.vigencia_desde,
          merged.vigencia_hasta,
          merged.estado_id,
          id,
          academiaId,
        ]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Tarifa no encontrada",
        });
      }

      const updated = await getTarifa(academiaId, id);

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

      if (isBusinessValidationError(err)) {
        return reply.code(400).send({
          ok: false,
          message: err.message,
        });
      }

      if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
        return reply.code(409).send({
          ok: false,
          message: "El plan o tipo de pago indicado no existe",
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar tarifa",
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

      const current = await getTarifa(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Tarifa no encontrada",
        });
      }

      if (await hasCargos(academiaId, id)) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La tarifa posee cargos asociados y no puede eliminarse. Debe cerrar su vigencia o desactivarla",
        });
      }

      if (await hasSucursalRelations(academiaId, id)) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La tarifa se encuentra asociada a una o más sucursales. Debe eliminar primero esas asociaciones",
        });
      }

      const [result]: any = await db.query(
        `
        DELETE FROM plan_tarifas
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
          message: "Tarifa no encontrada",
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
          message: "No se puede eliminar la tarifa porque está en uso",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar tarifa",
      });
    }
  });
}
