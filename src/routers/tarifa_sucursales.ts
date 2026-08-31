// src/routers/tarifa_sucursales.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * Tabla: tarifa_sucursal
 *
 * Campos:
 * - id
 * - academia_id
 * - tarifa_id
 * - sucursal_id
 * - created_at
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
 * - tarifa_id debe pertenecer a la academia efectiva.
 * - sucursal_id debe pertenecer a la academia efectiva.
 * - no se permite duplicar tarifa_id + sucursal_id.
 * - si la relación ya fue utilizada por cargos históricos,
 *   no puede modificarse ni eliminarse.
 */

/* =========================================================
   Schemas
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    tarifa_id: z.coerce.number().int().positive(),
    sucursal_id: z.coerce.number().int().positive(),
  })
  .strict();

const PutSchema = z
  .object({
    tarifa_id: z.coerce.number().int().positive(),
    sucursal_id: z.coerce.number().int().positive(),
  })
  .strict();

const PatchSchema = z
  .object({
    tarifa_id: z.coerce.number().int().positive().optional(),
    sucursal_id: z.coerce.number().int().positive().optional(),
  })
  .strict();

const QuerySchema = z
  .object({
    tarifa_id: z.coerce.number().int().positive().optional(),
    sucursal_id: z.coerce.number().int().positive().optional(),
    plan_id: z.coerce.number().int().positive().optional(),
    tipo_pago_id: z.coerce.number().int().positive().optional(),
    vigentes: z.enum(["1", "0"]).optional(),
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
    tarifa_id: Number(row.tarifa_id),
    sucursal_id: Number(row.sucursal_id),

    tarifa_nombre: row.tarifa_nombre == null ? undefined : String(row.tarifa_nombre),
    monto: row.monto == null ? undefined : Number(row.monto),
    vigencia_desde: row.vigencia_desde ?? undefined,
    vigencia_hasta: row.vigencia_hasta ?? undefined,
    tarifa_estado_id: row.tarifa_estado_id == null ? undefined : Number(row.tarifa_estado_id),

    plan_id: row.plan_id == null ? undefined : Number(row.plan_id),
    plan_nombre: row.plan_nombre == null ? undefined : String(row.plan_nombre),

    tipo_pago_id: row.tipo_pago_id == null ? undefined : Number(row.tipo_pago_id),
    tipo_pago_nombre: row.tipo_pago_nombre == null ? undefined : String(row.tipo_pago_nombre),

    sucursal_nombre: row.sucursal_nombre == null ? undefined : String(row.sucursal_nombre),

    created_at: row.created_at ?? null,
  };
}

async function getTarifaSucursal(academiaId: number, id: number) {
  const [rows]: any = await db.query(
    `
    SELECT
      ts.id,
      ts.academia_id,
      ts.tarifa_id,
      ts.sucursal_id,
      ts.created_at,

      pt.nombre AS tarifa_nombre,
      pt.monto,
      pt.vigencia_desde,
      pt.vigencia_hasta,
      pt.estado_id AS tarifa_estado_id,

      pa.id AS plan_id,
      pa.nombre AS plan_nombre,

      tp.id AS tipo_pago_id,
      tp.nombre AS tipo_pago_nombre,

      sr.nombre AS sucursal_nombre

    FROM tarifa_sucursal ts

    INNER JOIN plan_tarifas pt
      ON pt.id = ts.tarifa_id
     AND pt.academia_id = ts.academia_id

    INNER JOIN planes_academia pa
      ON pa.id = pt.plan_id
     AND pa.academia_id = ts.academia_id

    INNER JOIN tipo_pago tp
      ON tp.id = pt.tipo_pago_id
     AND (
       tp.academia_id IS NULL
       OR tp.academia_id = ts.academia_id
     )

    INNER JOIN sucursales_real sr
      ON sr.id = ts.sucursal_id
     AND sr.academia_id = ts.academia_id

    WHERE ts.id = ?
      AND ts.academia_id = ?

    LIMIT 1
    `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

async function validateTarifa(academiaId: number, tarifaId: number) {
  const [rows]: any = await db.query(
    `
    SELECT
      pt.id,
      pt.plan_id,
      pt.tipo_pago_id,
      pt.estado_id,

      pa.estado_id AS plan_estado_id

    FROM plan_tarifas pt

    INNER JOIN planes_academia pa
      ON pa.id = pt.plan_id
     AND pa.academia_id = pt.academia_id

    WHERE pt.id = ?
      AND pt.academia_id = ?

    LIMIT 1
    `,
    [tarifaId, academiaId]
  );

  if (!rows?.length) {
    throw new Error("La tarifa no existe o no pertenece a la academia");
  }

  if (Number(rows[0].plan_estado_id) !== 1) {
    throw new Error("El plan asociado a la tarifa no se encuentra activo");
  }
}

async function validateSucursal(academiaId: number, sucursalId: number) {
  const [rows]: any = await db.query(
    `
    SELECT id
    FROM sucursales_real
    WHERE id = ?
      AND academia_id = ?
    LIMIT 1
    `,
    [sucursalId, academiaId]
  );

  if (!rows?.length) {
    throw new Error("La sucursal no existe o no pertenece a la academia");
  }
}

/**
 * Además de pertenecer a la misma academia,
 * validamos que el plan correspondiente a la tarifa
 * esté disponible en la sucursal.
 *
 * Esto fuerza coherencia entre:
 *
 * plan_sucursal
 *        ↓
 * tarifa_sucursal
 */
async function validatePlanSucursalCompatibility(academiaId: number, tarifaId: number, sucursalId: number) {
  const [rows]: any = await db.query(
    `
    SELECT ps.id
    FROM plan_tarifas pt

    INNER JOIN plan_sucursal ps
      ON ps.plan_id = pt.plan_id
     AND ps.sucursal_id = ?
     AND ps.academia_id = ?

    WHERE pt.id = ?
      AND pt.academia_id = ?

    LIMIT 1
    `,
    [sucursalId, academiaId, tarifaId, academiaId]
  );

  if (!rows?.length) {
    throw new Error("El plan asociado a la tarifa no está disponible en esta sucursal");
  }
}

async function existsRelation(academiaId: number, tarifaId: number, sucursalId: number, excludeId?: number) {
  const values: any[] = [academiaId, tarifaId, sucursalId];

  let sql = `
    SELECT id
    FROM tarifa_sucursal
    WHERE academia_id = ?
      AND tarifa_id = ?
      AND sucursal_id = ?
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
 * Comprueba si esta combinación exacta tarifa+sucursal
 * ya fue utilizada por cargos financieros.
 *
 * cargos_jugador almacena ambos identificadores:
 * - tarifa_id
 * - sucursal_id
 */
async function relationHasCargos(academiaId: number, tarifaId: number, sucursalId: number) {
  const [rows]: any = await db.query(
    `
    SELECT id
    FROM cargos_jugador
    WHERE academia_id = ?
      AND tarifa_id = ?
      AND sucursal_id = ?
    LIMIT 1
    `,
    [academiaId, tarifaId, sucursalId]
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
    "La tarifa no existe o no pertenece a la academia",
    "La sucursal no existe o no pertenece a la academia",
    "El plan asociado a la tarifa no se encuentra activo",
    "El plan asociado a la tarifa no está disponible en esta sucursal",
  ].includes(String(err?.message ?? ""));
}

/* =========================================================
   Router
========================================================= */

export default async function tarifa_sucursales(app: FastifyInstance) {
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
        module: "tarifa_sucursal",
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
        message: "Error en módulo tarifa_sucursales",
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

      const where: string[] = ["ts.academia_id = ?"];
      const values: any[] = [academiaId];

      if (query.tarifa_id !== undefined) {
        where.push("ts.tarifa_id = ?");
        values.push(query.tarifa_id);
      }

      if (query.sucursal_id !== undefined) {
        where.push("ts.sucursal_id = ?");
        values.push(query.sucursal_id);
      }

      if (query.plan_id !== undefined) {
        where.push("pt.plan_id = ?");
        values.push(query.plan_id);
      }

      if (query.tipo_pago_id !== undefined) {
        where.push("pt.tipo_pago_id = ?");
        values.push(query.tipo_pago_id);
      }

      if (query.vigentes === "1") {
        where.push("pt.estado_id = 1");
        where.push("pt.vigencia_desde <= CURDATE()");
        where.push("(pt.vigencia_hasta IS NULL OR pt.vigencia_hasta >= CURDATE())");
      }

      if (query.vigentes === "0") {
        where.push(
          "(pt.estado_id <> 1 OR pt.vigencia_desde > CURDATE() OR (pt.vigencia_hasta IS NOT NULL AND pt.vigencia_hasta < CURDATE()))"
        );
      }

      values.push(query.limit);

      const [rows]: any = await db.query(
        `
        SELECT
          ts.id,
          ts.academia_id,
          ts.tarifa_id,
          ts.sucursal_id,
          ts.created_at,

          pt.nombre AS tarifa_nombre,
          pt.monto,
          pt.vigencia_desde,
          pt.vigencia_hasta,
          pt.estado_id AS tarifa_estado_id,

          pa.id AS plan_id,
          pa.nombre AS plan_nombre,

          tp.id AS tipo_pago_id,
          tp.nombre AS tipo_pago_nombre,

          sr.nombre AS sucursal_nombre

        FROM tarifa_sucursal ts

        INNER JOIN plan_tarifas pt
          ON pt.id = ts.tarifa_id
         AND pt.academia_id = ts.academia_id

        INNER JOIN planes_academia pa
          ON pa.id = pt.plan_id
         AND pa.academia_id = ts.academia_id

        INNER JOIN tipo_pago tp
          ON tp.id = pt.tipo_pago_id
         AND (
           tp.academia_id IS NULL
           OR tp.academia_id = ts.academia_id
         )

        INNER JOIN sucursales_real sr
          ON sr.id = ts.sucursal_id
         AND sr.academia_id = ts.academia_id

        WHERE ${where.join(" AND ")}

        ORDER BY
          pa.nombre ASC,
          sr.nombre ASC,
          tp.nombre ASC,
          pt.vigencia_desde DESC,
          ts.id DESC

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
        message: "Error al listar relaciones tarifa-sucursal",
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
      const row = await getTarifaSucursal(academiaId, parsed.data.id);

      reply.header("Cache-Control", "no-store");

      if (!row) {
        return reply.code(404).send({
          ok: false,
          message: "Relación tarifa-sucursal no encontrada",
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
        message: "Error al obtener relación tarifa-sucursal",
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

      await validateTarifa(academiaId, body.tarifa_id);
      await validateSucursal(academiaId, body.sucursal_id);
      await validatePlanSucursalCompatibility(academiaId, body.tarifa_id, body.sucursal_id);

      if (await existsRelation(academiaId, body.tarifa_id, body.sucursal_id)) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La tarifa ya está asociada a esta sucursal",
        });
      }

      const [result]: any = await db.query(
        `
        INSERT INTO tarifa_sucursal
          (academia_id, tarifa_id, sucursal_id)
        VALUES (?, ?, ?)
        `,
        [academiaId, body.tarifa_id, body.sucursal_id]
      );

      const insertId = Number(result?.insertId);
      const row = await getTarifaSucursal(academiaId, insertId);

      reply.header("Cache-Control", "no-store");

      return reply.code(201).send({
        ok: true,
        id: insertId,

        item: row
          ? normalize(row)
          : {
              id: insertId,
              academia_id: academiaId,
              tarifa_id: body.tarifa_id,
              sucursal_id: body.sucursal_id,
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
          message: "La tarifa ya está asociada a esta sucursal",
        });
      }

      if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
        return reply.code(409).send({
          ok: false,
          message: "La tarifa o sucursal indicada no existe",
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
        message: "Error al asociar tarifa con sucursal",
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

      return reply.code(400).send({
        ok: false,
        message: "ID inválido",
      });
    }

    try {
      const academiaId = resolveAcademiaId(req);
      const id = parsed.data.id;

      const current = await getTarifaSucursal(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Relación tarifa-sucursal no encontrada",
        });
      }

      const body = PutSchema.parse(req.body);

      const changed = body.tarifa_id !== Number(current.tarifa_id) || body.sucursal_id !== Number(current.sucursal_id);

      if (changed && (await relationHasCargos(academiaId, Number(current.tarifa_id), Number(current.sucursal_id)))) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La relación tarifa-sucursal ya fue utilizada en cargos y no puede modificarse",
        });
      }

      await validateTarifa(academiaId, body.tarifa_id);
      await validateSucursal(academiaId, body.sucursal_id);
      await validatePlanSucursalCompatibility(academiaId, body.tarifa_id, body.sucursal_id);

      if (await existsRelation(academiaId, body.tarifa_id, body.sucursal_id, id)) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "Ya existe otra asociación entre esta tarifa y esta sucursal",
        });
      }

      const [result]: any = await db.query(
        `
        UPDATE tarifa_sucursal
        SET
          tarifa_id = ?,
          sucursal_id = ?
        WHERE id = ?
          AND academia_id = ?
        LIMIT 1
        `,
        [body.tarifa_id, body.sucursal_id, id, academiaId]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Relación tarifa-sucursal no encontrada",
        });
      }

      const updated = await getTarifaSucursal(academiaId, id);

      return reply.send({
        ok: true,

        updated: updated
          ? normalize(updated)
          : {
              id,
              academia_id: academiaId,
              tarifa_id: body.tarifa_id,
              sucursal_id: body.sucursal_id,
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
          message: "Ya existe otra asociación entre esta tarifa y esta sucursal",
        });
      }

      if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
        return reply.code(409).send({
          ok: false,
          message: "La tarifa o sucursal indicada no existe",
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
        message: "Error al actualizar relación tarifa-sucursal",
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

      return reply.code(400).send({
        ok: false,
        message: "ID inválido",
      });
    }

    try {
      const academiaId = resolveAcademiaId(req);
      const id = parsed.data.id;

      const current = await getTarifaSucursal(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Relación tarifa-sucursal no encontrada",
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
        tarifa_id: body.tarifa_id ?? Number(current.tarifa_id),
        sucursal_id: body.sucursal_id ?? Number(current.sucursal_id),
      };

      const changed =
        merged.tarifa_id !== Number(current.tarifa_id) || merged.sucursal_id !== Number(current.sucursal_id);

      if (changed && (await relationHasCargos(academiaId, Number(current.tarifa_id), Number(current.sucursal_id)))) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La relación tarifa-sucursal ya fue utilizada en cargos y no puede modificarse",
        });
      }

      await validateTarifa(academiaId, merged.tarifa_id);
      await validateSucursal(academiaId, merged.sucursal_id);
      await validatePlanSucursalCompatibility(academiaId, merged.tarifa_id, merged.sucursal_id);

      if (await existsRelation(academiaId, merged.tarifa_id, merged.sucursal_id, id)) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "Ya existe otra asociación entre esta tarifa y esta sucursal",
        });
      }

      const [result]: any = await db.query(
        `
        UPDATE tarifa_sucursal
        SET
          tarifa_id = ?,
          sucursal_id = ?
        WHERE id = ?
          AND academia_id = ?
        LIMIT 1
        `,
        [merged.tarifa_id, merged.sucursal_id, id, academiaId]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Relación tarifa-sucursal no encontrada",
        });
      }

      const updated = await getTarifaSucursal(academiaId, id);

      return reply.send({
        ok: true,

        updated: updated
          ? normalize(updated)
          : {
              id,
              academia_id: academiaId,
              tarifa_id: merged.tarifa_id,
              sucursal_id: merged.sucursal_id,
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
          message: "Ya existe otra asociación entre esta tarifa y esta sucursal",
        });
      }

      if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
        return reply.code(409).send({
          ok: false,
          message: "La tarifa o sucursal indicada no existe",
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
        message: "Error al actualizar relación tarifa-sucursal",
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

      const current = await getTarifaSucursal(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Relación tarifa-sucursal no encontrada",
        });
      }

      if (await relationHasCargos(academiaId, Number(current.tarifa_id), Number(current.sucursal_id))) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La relación tarifa-sucursal ya fue utilizada para generar cargos y no puede eliminarse",
        });
      }

      const [result]: any = await db.query(
        `
        DELETE FROM tarifa_sucursal
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
          message: "Relación tarifa-sucursal no encontrada",
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
          message: "No se puede eliminar la relación porque está en uso",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar relación tarifa-sucursal",
      });
    }
  });
}
