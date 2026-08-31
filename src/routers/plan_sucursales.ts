// src/routers/plan_sucursales.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * Tabla: plan_sucursal
 *
 * Campos:
 * - id
 * - academia_id
 * - plan_id
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
 * Reglas:
 * - academia_id nunca se recibe desde el body.
 * - plan_id debe pertenecer a la academia efectiva.
 * - sucursal_id debe pertenecer a la academia efectiva.
 * - no se permite duplicar plan_id + sucursal_id.
 */

/* =========================================================
   Schemas
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    plan_id: z.coerce.number().int().positive(),
    sucursal_id: z.coerce.number().int().positive(),
  })
  .strict();

const PutSchema = z
  .object({
    plan_id: z.coerce.number().int().positive(),
    sucursal_id: z.coerce.number().int().positive(),
  })
  .strict();

const PatchSchema = z
  .object({
    plan_id: z.coerce.number().int().positive().optional(),
    sucursal_id: z.coerce.number().int().positive().optional(),
  })
  .strict();

const QuerySchema = z
  .object({
    plan_id: z.coerce.number().int().positive().optional(),
    sucursal_id: z.coerce.number().int().positive().optional(),
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
    sucursal_id: Number(row.sucursal_id),

    plan_nombre: row.plan_nombre == null ? undefined : String(row.plan_nombre),
    sucursal_nombre: row.sucursal_nombre == null ? undefined : String(row.sucursal_nombre),

    created_at: row.created_at ?? null,
  };
}

async function getPlanSucursal(academiaId: number, id: number) {
  const [rows]: any = await db.query(
    `
    SELECT
      ps.id,
      ps.academia_id,
      ps.plan_id,
      ps.sucursal_id,
      ps.created_at,
      pa.nombre AS plan_nombre,
      sr.nombre AS sucursal_nombre

    FROM plan_sucursal ps

    INNER JOIN planes_academia pa
      ON pa.id = ps.plan_id
     AND pa.academia_id = ps.academia_id

    INNER JOIN sucursales_real sr
      ON sr.id = ps.sucursal_id
     AND sr.academia_id = ps.academia_id

    WHERE ps.id = ?
      AND ps.academia_id = ?

    LIMIT 1
    `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

async function validatePlan(academiaId: number, planId: number) {
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

  if (Number(rows[0].estado_id) !== 1) {
    throw new Error("El plan seleccionado no se encuentra activo");
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

async function existsRelation(academiaId: number, planId: number, sucursalId: number, excludeId?: number) {
  const values: any[] = [academiaId, planId, sucursalId];

  let sql = `
    SELECT id
    FROM plan_sucursal
    WHERE academia_id = ?
      AND plan_id = ?
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
    "El plan no existe o no pertenece a la academia",
    "El plan seleccionado no se encuentra activo",
    "La sucursal no existe o no pertenece a la academia",
  ].includes(String(err?.message ?? ""));
}

/* =========================================================
   Router
========================================================= */

export default async function plan_sucursales(app: FastifyInstance) {
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
        module: "plan_sucursal",
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
        message: "Error en módulo plan_sucursales",
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

      const where: string[] = ["ps.academia_id = ?"];
      const values: any[] = [academiaId];

      if (query.plan_id !== undefined) {
        where.push("ps.plan_id = ?");
        values.push(query.plan_id);
      }

      if (query.sucursal_id !== undefined) {
        where.push("ps.sucursal_id = ?");
        values.push(query.sucursal_id);
      }

      values.push(query.limit);

      const [rows]: any = await db.query(
        `
        SELECT
          ps.id,
          ps.academia_id,
          ps.plan_id,
          ps.sucursal_id,
          ps.created_at,
          pa.nombre AS plan_nombre,
          sr.nombre AS sucursal_nombre

        FROM plan_sucursal ps

        INNER JOIN planes_academia pa
          ON pa.id = ps.plan_id
         AND pa.academia_id = ps.academia_id

        INNER JOIN sucursales_real sr
          ON sr.id = ps.sucursal_id
         AND sr.academia_id = ps.academia_id

        WHERE ${where.join(" AND ")}

        ORDER BY
          pa.nombre ASC,
          sr.nombre ASC,
          ps.id ASC

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
        message: "Error al listar sucursales de planes",
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
      const row = await getPlanSucursal(academiaId, parsed.data.id);

      reply.header("Cache-Control", "no-store");

      if (!row) {
        return reply.code(404).send({
          ok: false,
          message: "Relación plan-sucursal no encontrada",
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
        message: "Error al obtener relación plan-sucursal",
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

      await validatePlan(academiaId, body.plan_id);
      await validateSucursal(academiaId, body.sucursal_id);

      const duplicate = await existsRelation(academiaId, body.plan_id, body.sucursal_id);

      if (duplicate) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "El plan ya está asociado a esta sucursal",
        });
      }

      const [result]: any = await db.query(
        `
        INSERT INTO plan_sucursal
          (academia_id, plan_id, sucursal_id)
        VALUES (?, ?, ?)
        `,
        [academiaId, body.plan_id, body.sucursal_id]
      );

      const insertId = Number(result?.insertId);
      const row = await getPlanSucursal(academiaId, insertId);

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
          message: "El plan ya está asociado a esta sucursal",
        });
      }

      if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
        return reply.code(409).send({
          ok: false,
          message: "El plan o la sucursal indicada no existe",
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
        message: "Error al asociar plan con sucursal",
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

      const current = await getPlanSucursal(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Relación plan-sucursal no encontrada",
        });
      }

      const body = PutSchema.parse(req.body);

      await validatePlan(academiaId, body.plan_id);
      await validateSucursal(academiaId, body.sucursal_id);

      const duplicate = await existsRelation(academiaId, body.plan_id, body.sucursal_id, id);

      if (duplicate) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "Ya existe otra asociación entre este plan y esta sucursal",
        });
      }

      const [result]: any = await db.query(
        `
        UPDATE plan_sucursal
        SET plan_id = ?, sucursal_id = ?
        WHERE id = ?
          AND academia_id = ?
        LIMIT 1
        `,
        [body.plan_id, body.sucursal_id, id, academiaId]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Relación plan-sucursal no encontrada",
        });
      }

      const updated = await getPlanSucursal(academiaId, id);

      return reply.send({
        ok: true,
        updated: updated
          ? normalize(updated)
          : {
              id,
              academia_id: academiaId,
              plan_id: body.plan_id,
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
          message: "Ya existe otra asociación entre este plan y esta sucursal",
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
        message: "Error al actualizar relación plan-sucursal",
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

      const current = await getPlanSucursal(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Relación plan-sucursal no encontrada",
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
        plan_id: body.plan_id ?? Number(current.plan_id),
        sucursal_id: body.sucursal_id ?? Number(current.sucursal_id),
      };

      await validatePlan(academiaId, merged.plan_id);
      await validateSucursal(academiaId, merged.sucursal_id);

      const duplicate = await existsRelation(academiaId, merged.plan_id, merged.sucursal_id, id);

      if (duplicate) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "Ya existe otra asociación entre este plan y esta sucursal",
        });
      }

      const [result]: any = await db.query(
        `
        UPDATE plan_sucursal
        SET plan_id = ?, sucursal_id = ?
        WHERE id = ?
          AND academia_id = ?
        LIMIT 1
        `,
        [merged.plan_id, merged.sucursal_id, id, academiaId]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Relación plan-sucursal no encontrada",
        });
      }

      const updated = await getPlanSucursal(academiaId, id);

      return reply.send({
        ok: true,
        updated: updated
          ? normalize(updated)
          : {
              id,
              academia_id: academiaId,
              plan_id: merged.plan_id,
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
          message: "Ya existe otra asociación entre este plan y esta sucursal",
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
        message: "Error al actualizar relación plan-sucursal",
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

      const current = await getPlanSucursal(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Relación plan-sucursal no encontrada",
        });
      }

      const [result]: any = await db.query(
        `
        DELETE FROM plan_sucursal
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
          message: "Relación plan-sucursal no encontrada",
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
        message: "Error al eliminar relación plan-sucursal",
      });
    }
  });
}
