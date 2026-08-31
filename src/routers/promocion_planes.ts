// src/routers/promocion_planes.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * Tabla: promocion_plan
 *
 * Campos:
 * - id
 * - academia_id
 * - promocion_id
 * - plan_id
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
 * - academia_id nunca se acepta desde el body.
 * - promocion_id debe pertenecer a la academia efectiva.
 * - plan_id debe pertenecer a la academia efectiva.
 * - no se permite duplicar promocion_id + plan_id.
 * - si la relación ya fue utilizada para generar cargos, no puede
 *   modificarse ni eliminarse.
 */

/* =========================================================
   Schemas
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    promocion_id: z.coerce.number().int().positive(),
    plan_id: z.coerce.number().int().positive(),
  })
  .strict();

const PutSchema = z
  .object({
    promocion_id: z.coerce.number().int().positive(),
    plan_id: z.coerce.number().int().positive(),
  })
  .strict();

const PatchSchema = z
  .object({
    promocion_id: z.coerce.number().int().positive().optional(),
    plan_id: z.coerce.number().int().positive().optional(),
  })
  .strict();

const QuerySchema = z
  .object({
    promocion_id: z.coerce.number().int().positive().optional(),
    plan_id: z.coerce.number().int().positive().optional(),
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
    promocion_id: Number(row.promocion_id),
    plan_id: Number(row.plan_id),

    promocion_nombre: row.promocion_nombre == null ? undefined : String(row.promocion_nombre),
    tipo_beneficio: row.tipo_beneficio == null ? undefined : String(row.tipo_beneficio),
    valor: row.valor == null ? undefined : Number(row.valor),

    fecha_desde: row.fecha_desde ?? undefined,
    fecha_hasta: row.fecha_hasta ?? undefined,

    promocion_estado_id: row.promocion_estado_id == null ? undefined : Number(row.promocion_estado_id),

    plan_nombre: row.plan_nombre == null ? undefined : String(row.plan_nombre),
    periodicidad: row.periodicidad == null ? undefined : String(row.periodicidad),
    plan_estado_id: row.plan_estado_id == null ? undefined : Number(row.plan_estado_id),

    created_at: row.created_at ?? null,
  };
}

async function getPromocionPlan(academiaId: number, id: number) {
  const [rows]: any = await db.query(
    `
    SELECT
      pp.id,
      pp.academia_id,
      pp.promocion_id,
      pp.plan_id,
      pp.created_at,

      p.nombre AS promocion_nombre,
      p.tipo_beneficio,
      p.valor,
      p.fecha_desde,
      p.fecha_hasta,
      p.estado_id AS promocion_estado_id,

      pa.nombre AS plan_nombre,
      pa.periodicidad,
      pa.estado_id AS plan_estado_id

    FROM promocion_plan pp

    INNER JOIN promociones_academia p
      ON p.id = pp.promocion_id
     AND p.academia_id = pp.academia_id

    INNER JOIN planes_academia pa
      ON pa.id = pp.plan_id
     AND pa.academia_id = pp.academia_id

    WHERE pp.id = ?
      AND pp.academia_id = ?

    LIMIT 1
    `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

async function validatePromocion(academiaId: number, promocionId: number) {
  const [rows]: any = await db.query(
    `
    SELECT id
    FROM promociones_academia
    WHERE id = ?
      AND academia_id = ?
    LIMIT 1
    `,
    [promocionId, academiaId]
  );

  if (!rows?.length) {
    throw new Error("La promoción no existe o no pertenece a la academia");
  }
}

async function validatePlan(academiaId: number, planId: number) {
  const [rows]: any = await db.query(
    `
    SELECT id
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
}

async function existsRelation(academiaId: number, promocionId: number, planId: number, excludeId?: number) {
  const values: any[] = [academiaId, promocionId, planId];

  let sql = `
    SELECT id
    FROM promocion_plan
    WHERE academia_id = ?
      AND promocion_id = ?
      AND plan_id = ?
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
 * Determina si esta relación promoción + plan
 * ya fue utilizada por algún cargo histórico.
 *
 * cargos_jugador almacena promocion_id.
 * jugador_plan nos permite recuperar el plan utilizado.
 */
async function relationHasCargos(academiaId: number, promocionId: number, planId: number) {
  const [rows]: any = await db.query(
    `
    SELECT c.id
    FROM cargos_jugador c

    INNER JOIN jugador_plan jp
      ON jp.id = c.jugador_plan_id
     AND jp.academia_id = c.academia_id

    WHERE c.academia_id = ?
      AND c.promocion_id = ?
      AND jp.plan_id = ?

    LIMIT 1
    `,
    [academiaId, promocionId, planId]
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
    "La promoción no existe o no pertenece a la academia",
    "El plan no existe o no pertenece a la academia",
  ].includes(String(err?.message ?? ""));
}

/* =========================================================
   Router
========================================================= */

export default async function promocion_planes(app: FastifyInstance) {
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
        module: "promocion_plan",
        status: "ready",
        academia_id: academiaId,
        timestamp: new Date().toISOString(),
      });
    } catch (err: any) {
      const handled = handleScopeError(reply, err);
      if (handled) return handled;

      reply.header("Cache-Control", "no-store");
      return reply.code(500).send({ ok: false, message: "Error en módulo promocion_planes" });
    }
  });

  /* =======================================================
     GET /
  ======================================================= */

  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academiaId = resolveAcademiaId(req);
      const query = QuerySchema.parse(req.query);

      const where: string[] = ["pp.academia_id = ?"];
      const values: any[] = [academiaId];

      if (query.promocion_id !== undefined) {
        where.push("pp.promocion_id = ?");
        values.push(query.promocion_id);
      }

      if (query.plan_id !== undefined) {
        where.push("pp.plan_id = ?");
        values.push(query.plan_id);
      }

      values.push(query.limit);

      const [rows]: any = await db.query(
        `
        SELECT
          pp.id,
          pp.academia_id,
          pp.promocion_id,
          pp.plan_id,
          pp.created_at,

          p.nombre AS promocion_nombre,
          p.tipo_beneficio,
          p.valor,
          p.fecha_desde,
          p.fecha_hasta,
          p.estado_id AS promocion_estado_id,

          pa.nombre AS plan_nombre,
          pa.periodicidad,
          pa.estado_id AS plan_estado_id

        FROM promocion_plan pp

        INNER JOIN promociones_academia p
          ON p.id = pp.promocion_id
         AND p.academia_id = pp.academia_id

        INNER JOIN planes_academia pa
          ON pa.id = pp.plan_id
         AND pa.academia_id = pp.academia_id

        WHERE ${where.join(" AND ")}

        ORDER BY
          p.nombre ASC,
          pa.nombre ASC,
          pp.id ASC

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
        message: "Error al listar relaciones promoción-plan",
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
      const row = await getPromocionPlan(academiaId, parsed.data.id);

      reply.header("Cache-Control", "no-store");

      if (!row) {
        return reply.code(404).send({
          ok: false,
          message: "Relación promoción-plan no encontrada",
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
        message: "Error al obtener relación promoción-plan",
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

      await validatePromocion(academiaId, body.promocion_id);
      await validatePlan(academiaId, body.plan_id);

      const duplicate = await existsRelation(academiaId, body.promocion_id, body.plan_id);

      if (duplicate) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La promoción ya está asociada a este plan",
        });
      }

      const [result]: any = await db.query(
        `
        INSERT INTO promocion_plan
          (academia_id, promocion_id, plan_id)
        VALUES (?, ?, ?)
        `,
        [academiaId, body.promocion_id, body.plan_id]
      );

      const insertId = Number(result?.insertId);
      const row = await getPromocionPlan(academiaId, insertId);

      reply.header("Cache-Control", "no-store");

      return reply.code(201).send({
        ok: true,
        id: insertId,

        item: row
          ? normalize(row)
          : {
              id: insertId,
              academia_id: academiaId,
              promocion_id: body.promocion_id,
              plan_id: body.plan_id,
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
          message: "La promoción ya está asociada a este plan",
        });
      }

      if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
        return reply.code(409).send({
          ok: false,
          message: "La promoción o el plan indicado no existe",
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
        message: "Error al asociar promoción con plan",
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

      const current = await getPromocionPlan(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Relación promoción-plan no encontrada",
        });
      }

      const body = PutSchema.parse(req.body);

      /*
       * Si ya se utilizó esta relación para generar cargos,
       * no permitimos convertirla en una asociación diferente.
       */
      const used = await relationHasCargos(academiaId, Number(current.promocion_id), Number(current.plan_id));

      if (used && (body.promocion_id !== Number(current.promocion_id) || body.plan_id !== Number(current.plan_id))) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La relación promoción-plan ya fue utilizada en cargos y no puede modificarse",
        });
      }

      await validatePromocion(academiaId, body.promocion_id);
      await validatePlan(academiaId, body.plan_id);

      const duplicate = await existsRelation(academiaId, body.promocion_id, body.plan_id, id);

      if (duplicate) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "Ya existe otra asociación entre esta promoción y este plan",
        });
      }

      const [result]: any = await db.query(
        `
        UPDATE promocion_plan
        SET
          promocion_id = ?,
          plan_id = ?
        WHERE id = ?
          AND academia_id = ?
        LIMIT 1
        `,
        [body.promocion_id, body.plan_id, id, academiaId]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Relación promoción-plan no encontrada",
        });
      }

      const updated = await getPromocionPlan(academiaId, id);

      return reply.send({
        ok: true,
        updated: updated
          ? normalize(updated)
          : {
              id,
              academia_id: academiaId,
              promocion_id: body.promocion_id,
              plan_id: body.plan_id,
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
          message: "Ya existe otra asociación entre esta promoción y este plan",
        });
      }

      if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
        return reply.code(409).send({
          ok: false,
          message: "La promoción o el plan indicado no existe",
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
        message: "Error al actualizar relación promoción-plan",
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

      const current = await getPromocionPlan(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Relación promoción-plan no encontrada",
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
        promocion_id: body.promocion_id ?? Number(current.promocion_id),
        plan_id: body.plan_id ?? Number(current.plan_id),
      };

      const changed =
        merged.promocion_id !== Number(current.promocion_id) || merged.plan_id !== Number(current.plan_id);

      if (changed && (await relationHasCargos(academiaId, Number(current.promocion_id), Number(current.plan_id)))) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La relación promoción-plan ya fue utilizada en cargos y no puede modificarse",
        });
      }

      await validatePromocion(academiaId, merged.promocion_id);
      await validatePlan(academiaId, merged.plan_id);

      const duplicate = await existsRelation(academiaId, merged.promocion_id, merged.plan_id, id);

      if (duplicate) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "Ya existe otra asociación entre esta promoción y este plan",
        });
      }

      const [result]: any = await db.query(
        `
        UPDATE promocion_plan
        SET
          promocion_id = ?,
          plan_id = ?
        WHERE id = ?
          AND academia_id = ?
        LIMIT 1
        `,
        [merged.promocion_id, merged.plan_id, id, academiaId]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Relación promoción-plan no encontrada",
        });
      }

      const updated = await getPromocionPlan(academiaId, id);

      return reply.send({
        ok: true,

        updated: updated
          ? normalize(updated)
          : {
              id,
              academia_id: academiaId,
              promocion_id: merged.promocion_id,
              plan_id: merged.plan_id,
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
          message: "Ya existe otra asociación entre esta promoción y este plan",
        });
      }

      if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
        return reply.code(409).send({
          ok: false,
          message: "La promoción o el plan indicado no existe",
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
        message: "Error al actualizar relación promoción-plan",
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

      const current = await getPromocionPlan(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Relación promoción-plan no encontrada",
        });
      }

      /*
       * Conservación de trazabilidad histórica.
       */
      if (await relationHasCargos(academiaId, Number(current.promocion_id), Number(current.plan_id))) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La relación promoción-plan ya fue utilizada para generar cargos y no puede eliminarse",
        });
      }

      const [result]: any = await db.query(
        `
        DELETE FROM promocion_plan
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
          message: "Relación promoción-plan no encontrada",
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
        message: "Error al eliminar relación promoción-plan",
      });
    }
  });
}
