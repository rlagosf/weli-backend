// src/routers/planes.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z, ZodError } from "zod";

import { db } from "../db";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * Tablas:
 *
 * - planes_catalogo
 * - academia_plan
 * - plan_reglas
 *
 * Modelo:
 *
 * planes_catalogo
 *      Catálogo GLOBAL de planes/beneficios.
 *
 * academia_plan
 *      Determina qué planes están habilitados
 *      para una academia.
 *
 * plan_reglas
 *      Define las reglas globales de beneficio.
 *
 * Seguridad:
 * - READ: roles 1, 3
 * - WRITE: roles 1, 3
 *
 * academia_id:
 * - Admin: academia firmada en JWT.
 * - Superadmin: x-academia-id validado.
 *
 * Nunca se recibe academia_id desde el body.
 */

/* =========================================================
   SCHEMAS
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

/*
 * id corresponde al ID de la relación academia_plan.
 *
 * plan_id corresponde al ID global de planes_catalogo.
 */

const CreateSchema = z
  .object({
    plan_id: z.coerce.number().int().positive(),

    estado_id: z.coerce.number().int().positive().max(255).default(1),
  })
  .strict();

const PutSchema = z
  .object({
    plan_id: z.coerce.number().int().positive(),

    estado_id: z.coerce.number().int().positive().max(255),
  })
  .strict();

const PatchSchema = z
  .object({
    plan_id: z.coerce.number().int().positive().optional(),

    estado_id: z.coerce.number().int().positive().max(255).optional(),
  })
  .strict();

/* =========================================================
   HELPERS
========================================================= */

function zodDetail(err: ZodError): string {
  return err.issues.map((issue) => `${issue.path.join(".") || "field"}: ${issue.message}`).join("; ");
}

/* =========================================================
   ACADEMIA EFECTIVA
========================================================= */

function resolveAcademiaId(req: FastifyRequest): number {
  const academiaId = Number(getEffectiveAcademiaId(req));

  if (!Number.isInteger(academiaId) || academiaId <= 0) {
    const error: any = new Error("Academia efectiva inválida");

    error.statusCode = 403;

    throw error;
  }

  return academiaId;
}

/* =========================================================
   NORMALIZACIÓN
========================================================= */

function normalize(row: any) {
  return {
    /*
     * ID de academia_plan.
     */
    id: Number(row.id),

    academia_id: Number(row.academia_id),

    /*
     * ID del catálogo global.
     */
    plan_id: Number(row.plan_id),

    nombre: String(row.nombre ?? ""),

    descripcion: row.descripcion == null ? null : String(row.descripcion),

    estado_id: Number(row.estado_id),

    catalogo_estado_id: row.catalogo_estado_id == null ? null : Number(row.catalogo_estado_id),

    created_at: row.created_at ?? null,

    updated_at: row.updated_at ?? null,
  };
}

/* =========================================================
   PLAN GLOBAL
========================================================= */

async function validatePlanGlobal(planId: number) {
  const [rows]: any = await db.query(
    `
        SELECT
          id

        FROM planes_catalogo

        WHERE id = ?

        LIMIT 1
      `,
    [planId]
  );

  if (!rows?.length) {
    throw new Error("El plan no existe en el catálogo global");
  }
}

/* =========================================================
   RELACIÓN ACADEMIA_PLAN
========================================================= */

async function getRelacion(academiaId: number, id: number) {
  const [rows]: any = await db.query(
    `
        SELECT
          ap.id,
          ap.academia_id,
          ap.plan_id,
          ap.estado_id,

          ap.created_at,
          ap.updated_at,

          pc.nombre,
          pc.descripcion,

          pc.estado_id
            AS catalogo_estado_id

        FROM academia_plan ap

        INNER JOIN planes_catalogo pc
          ON pc.id =
             ap.plan_id

        WHERE ap.id = ?
          AND ap.academia_id = ?

        LIMIT 1
      `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

async function existsRelation(academiaId: number, planId: number, excludeId?: number): Promise<boolean> {
  const values: any[] = [academiaId, planId];

  let sql = `
    SELECT id

    FROM academia_plan

    WHERE academia_id = ?
      AND plan_id = ?
  `;

  if (excludeId !== undefined) {
    sql += `
      AND id <> ?
    `;

    values.push(excludeId);
  }

  sql += `
    LIMIT 1
  `;

  const [rows]: any = await db.query(sql, values);

  return Array.isArray(rows) && rows.length > 0;
}

/* =========================================================
   REGLAS DEL PLAN
========================================================= */

async function getPlanReglas(planId: number) {
  const [rows]: any = await db.query(
    `
        SELECT
          pr.id,
          pr.plan_id,
          pr.tipo_pago_id,

          tp.nombre
            AS tipo_pago_nombre,

          pr.tipo_beneficio,
          pr.valor,
          pr.estado_id,
          pr.created_at,
          pr.updated_at

        FROM plan_reglas pr

        LEFT JOIN tipo_pago tp
          ON tp.id =
             pr.tipo_pago_id

        WHERE pr.plan_id = ?

        ORDER BY
          pr.id ASC
      `,
    [planId]
  );

  return rows ?? [];
}

/* =========================================================
   DEPENDENCIAS
========================================================= */

/**
 * Si una academia ya utilizó el plan para:
 *
 * - asignarlo a un jugador
 * - registrar un pago
 *
 * no permitimos transformar esa misma relación
 * academia_plan hacia otro plan global.
 *
 * Desactivar la relación sigue siendo posible
 * modificando estado_id.
 */

async function relationHasDependencies(
  academiaId: number,
  planId: number
): Promise<{
  used: boolean;
  source: string | null;
}> {
  /* -------------------------------------------------------
     PLAN ASIGNADO A JUGADOR
  ------------------------------------------------------- */

  const [jugadores]: any = await db.query(
    `
        SELECT id

        FROM jugador_plan_catalogo

        WHERE academia_id = ?
          AND plan_id = ?

        LIMIT 1
      `,
    [academiaId, planId]
  );

  if (jugadores?.length) {
    return {
      used: true,
      source: "jugador_plan_catalogo",
    };
  }

  /* -------------------------------------------------------
     PLAN REGISTRADO EN PAGOS
  ------------------------------------------------------- */

  const [pagos]: any = await db.query(
    `
        SELECT id

        FROM pagos_jugador

        WHERE academia_id = ?
          AND plan_catalogo_id = ?

        LIMIT 1
      `,
    [academiaId, planId]
  );

  if (pagos?.length) {
    return {
      used: true,
      source: "pagos_jugador",
    };
  }

  return {
    used: false,
    source: null,
  };
}

/* =========================================================
   ERRORES DE SCOPE
========================================================= */

function scopeError(reply: FastifyReply, err: any) {
  const status = Number(err?.statusCode ?? 0);

  if (status === 400 || status === 401 || status === 403) {
    reply.header("Cache-Control", "no-store");

    return reply.code(status).send({
      ok: false,

      message: err?.message || "No fue posible determinar la academia efectiva",
    });
  }

  return null;
}

/* =========================================================
   ERRORES DE NEGOCIO
========================================================= */

function isBusinessValidationError(err: any) {
  return ["El plan no existe en el catálogo global"].includes(String(err?.message ?? ""));
}

/* =========================================================
   ROUTER
========================================================= */

export default async function planes(app: FastifyInstance) {
  /*
   * Seguridad conservada exactamente
   * según router original.
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
        const academiaId = resolveAcademiaId(req);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          module: "academia_plan",

          status: "ready",

          academia_id: academiaId,

          timestamp: new Date().toISOString(),
        });
      } catch (err: any) {
        const handled = scopeError(reply, err);

        if (handled) {
          return handled;
        }

        reply.header("Cache-Control", "no-store");

        return reply.code(500).send({
          ok: false,

          message: "Error en módulo de planes",
        });
      }
    }
  );

  /* =======================================================
     GET /
     PLANES HABILITADOS PARA LA ACADEMIA
  ======================================================= */

  app.get(
    "/",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const academiaId = resolveAcademiaId(req);

        const [rows]: any = await db.query(
          `
              SELECT
                ap.id,
                ap.academia_id,
                ap.plan_id,
                ap.estado_id,

                ap.created_at,
                ap.updated_at,

                pc.nombre,
                pc.descripcion,

                pc.estado_id
                  AS catalogo_estado_id

              FROM academia_plan ap

              INNER JOIN planes_catalogo pc
                ON pc.id =
                   ap.plan_id

              WHERE ap.academia_id = ?

              ORDER BY
                ap.estado_id ASC,
                pc.nombre ASC,
                pc.id ASC
            `,
          [academiaId]
        );

        const items: any[] = [];

        for (const row of rows ?? []) {
          const item = normalize(row);

          const reglas = await getPlanReglas(item.plan_id);

          items.push({
            ...item,
            reglas,
          });
        }

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          academia_id: academiaId,

          count: items.length,

          items,
        });
      } catch (err: any) {
        const handled = scopeError(reply, err);

        if (handled) {
          return handled;
        }

        reply.header("Cache-Control", "no-store");

        return reply.code(500).send({
          ok: false,

          message: "Error al listar planes",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
   GET /catalogo
   CATÁLOGO GLOBAL DE PLANES
======================================================= */

  app.get(
    "/catalogo",
    {
      preHandler: canRead,
    },
    async (_req: FastifyRequest, reply: FastifyReply) => {
      try {
        const [rows]: any = await db.query(
          `
            SELECT
              pc.id,
              pc.nombre,
              pc.descripcion,
              pc.estado_id,
              pc.created_at,
              pc.updated_at

            FROM planes_catalogo pc

            ORDER BY
              pc.estado_id ASC,
              pc.nombre ASC,
              pc.id ASC
          `
        );

        const items: any[] = [];

        for (const row of rows ?? []) {
          const reglas = await getPlanReglas(Number(row.id));

          items.push({
            id: Number(row.id),

            nombre: String(row.nombre ?? ""),

            descripcion: row.descripcion == null ? null : String(row.descripcion),

            estado_id: Number(row.estado_id),

            created_at: row.created_at ?? null,

            updated_at: row.updated_at ?? null,

            reglas,
          });
        }

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          count: items.length,

          items,
        });
      } catch (err: any) {
        reply.header("Cache-Control", "no-store");

        return reply.code(500).send({
          ok: false,

          message: "Error al listar catálogo global de planes",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     GET /:id
     RELACIÓN ACADEMIA_PLAN
  ======================================================= */

  app.get(
    "/:id",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
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

        const row = await getRelacion(academiaId, id);

        reply.header("Cache-Control", "no-store");

        if (!row) {
          return reply.code(404).send({
            ok: false,

            message: "Plan no encontrado",
          });
        }

        const item = normalize(row);

        const reglas = await getPlanReglas(item.plan_id);

        return reply.send({
          ok: true,

          item: {
            ...item,
            reglas,
          },
        });
      } catch (err: any) {
        const handled = scopeError(reply, err);

        if (handled) {
          return handled;
        }

        reply.header("Cache-Control", "no-store");

        return reply.code(500).send({
          ok: false,

          message: "Error al obtener plan",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     POST /
     HABILITAR PLAN GLOBAL EN ACADEMIA
  ======================================================= */

  app.post(
    "/",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const academiaId = resolveAcademiaId(req);

        /*
         * Schema strict().
         *
         * academia_id nunca se acepta
         * desde el body.
         */
        const body = CreateSchema.parse(req.body);

        const planId = Number(body.plan_id);

        const estadoId = Number(body.estado_id);

        await validatePlanGlobal(planId);

        const duplicate = await existsRelation(academiaId, planId);

        if (duplicate) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "Este plan ya se encuentra asociado a la academia",
          });
        }

        const [result]: any = await db.query(
          `
              INSERT INTO academia_plan (
                academia_id,
                plan_id,
                estado_id
              )

              VALUES (?, ?, ?)
            `,
          [academiaId, planId, estadoId]
        );

        const insertId = Number(result?.insertId);

        const row = await getRelacion(academiaId, insertId);

        reply.header("Cache-Control", "no-store");

        if (row) {
          const item = normalize(row);

          const reglas = await getPlanReglas(item.plan_id);

          return reply.code(201).send({
            ok: true,

            id: insertId,

            item: {
              ...item,
              reglas,
            },
          });
        }

        return reply.code(201).send({
          ok: true,

          id: insertId,

          item: {
            id: insertId,

            academia_id: academiaId,

            plan_id: planId,

            estado_id: estadoId,
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

        const handled = scopeError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "Este plan ya se encuentra asociado a la academia",
          });
        }

        if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
          return reply.code(409).send({
            ok: false,

            message: "La academia o el plan indicado no existe",
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

          message: "Error al asociar plan con academia",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     PUT /:id
     REEMPLAZO DE RELACIÓN
  ======================================================= */

  app.put(
    "/:id",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
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

        const current = await getRelacion(academiaId, id);

        if (!current) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Plan no encontrado",
          });
        }

        const body = PutSchema.parse(req.body);

        const planId = Number(body.plan_id);

        const estadoId = Number(body.estado_id);

        const changingPlan = planId !== Number(current.plan_id);

        /*
         * Si el plan ya fue utilizado,
         * no permitimos transformar la relación
         * hacia otro plan del catálogo.
         *
         * Cambiar únicamente estado_id sí es válido.
         */
        if (changingPlan) {
          const dependencies = await relationHasDependencies(academiaId, Number(current.plan_id));

          if (dependencies.used) {
            reply.header("Cache-Control", "no-store");

            return reply.code(409).send({
              ok: false,

              message:
                "La asociación actual está siendo utilizada y no puede cambiarse a otro plan. Puede desactivarse mediante estado_id",
            });
          }
        }

        await validatePlanGlobal(planId);

        const duplicate = await existsRelation(academiaId, planId, id);

        if (duplicate) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "Ya existe otra asociación de esta academia con ese plan",
          });
        }

        const [result]: any = await db.query(
          `
              UPDATE academia_plan

              SET
                plan_id = ?,
                estado_id = ?

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [planId, estadoId, id, academiaId]
        );

        reply.header("Cache-Control", "no-store");

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,

            message: "Plan no encontrado",
          });
        }

        const row = await getRelacion(academiaId, id);

        if (row) {
          const item = normalize(row);

          const reglas = await getPlanReglas(item.plan_id);

          return reply.send({
            ok: true,

            updated: {
              ...item,
              reglas,
            },
          });
        }

        return reply.send({
          ok: true,

          updated: {
            id,

            academia_id: academiaId,

            plan_id: planId,

            estado_id: estadoId,
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

        const handled = scopeError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "Ya existe otra asociación de esta academia con ese plan",
          });
        }

        if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
          return reply.code(409).send({
            ok: false,

            message: "La academia o el plan indicado no existe",
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

          message: "Error al actualizar plan",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     PATCH /:id
  ======================================================= */

  app.patch(
    "/:id",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
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

        const current = await getRelacion(academiaId, id);

        if (!current) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Plan no encontrado",
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

        const planId = body.plan_id !== undefined ? Number(body.plan_id) : Number(current.plan_id);

        const estadoId = body.estado_id !== undefined ? Number(body.estado_id) : Number(current.estado_id);

        const changingPlan = planId !== Number(current.plan_id);

        if (changingPlan) {
          const dependencies = await relationHasDependencies(academiaId, Number(current.plan_id));

          if (dependencies.used) {
            reply.header("Cache-Control", "no-store");

            return reply.code(409).send({
              ok: false,

              message:
                "La asociación actual está siendo utilizada y no puede cambiarse a otro plan. Puede desactivarse mediante estado_id",
            });
          }

          await validatePlanGlobal(planId);

          const duplicate = await existsRelation(academiaId, planId, id);

          if (duplicate) {
            reply.header("Cache-Control", "no-store");

            return reply.code(409).send({
              ok: false,

              message: "Ya existe otra asociación de esta academia con ese plan",
            });
          }
        }

        const fields: string[] = [];

        const values: any[] = [];

        if (body.plan_id !== undefined) {
          fields.push("plan_id = ?");

          values.push(planId);
        }

        if (body.estado_id !== undefined) {
          fields.push("estado_id = ?");

          values.push(estadoId);
        }

        if (fields.length === 0) {
          reply.header("Cache-Control", "no-store");

          return reply.code(400).send({
            ok: false,

            message: "No hay campos válidos para actualizar",
          });
        }

        values.push(id, academiaId);

        const [result]: any = await db.query(
          `
              UPDATE academia_plan

              SET
                ${fields.join(", ")}

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          values
        );

        reply.header("Cache-Control", "no-store");

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,

            message: "Plan no encontrado",
          });
        }

        const row = await getRelacion(academiaId, id);

        if (row) {
          const item = normalize(row);

          const reglas = await getPlanReglas(item.plan_id);

          return reply.send({
            ok: true,

            updated: {
              ...item,
              reglas,
            },
          });
        }

        return reply.send({
          ok: true,

          updated: {
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

        const handled = scopeError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "Ya existe otra asociación de esta academia con ese plan",
          });
        }

        if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
          return reply.code(409).send({
            ok: false,

            message: "La academia o el plan indicado no existe",
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

          message: "Error al actualizar plan",

          detail: err?.message,
        });
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

        const current = await getRelacion(academiaId, id);

        if (!current) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Plan no encontrado",
          });
        }

        const dependencies = await relationHasDependencies(academiaId, Number(current.plan_id));

        if (dependencies.used) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message:
              "El plan está siendo utilizado por jugadores o pagos y no puede eliminarse de la academia. Debe desactivarse mediante estado_id",
          });
        }

        const [result]: any = await db.query(
          `
              DELETE
              FROM academia_plan

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

            message: "Plan no encontrado",
          });
        }

        return reply.send({
          ok: true,

          deleted: id,
        });
      } catch (err: any) {
        reply.header("Cache-Control", "no-store");

        const handled = scopeError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1451 || String(err?.code ?? "").includes("ER_ROW_IS_REFERENCED")) {
          return reply.code(409).send({
            ok: false,

            message: "No se puede eliminar el plan porque está en uso",

            detail: err?.sqlMessage ?? err?.message,
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al eliminar plan",

          detail: err?.message,
        });
      }
    }
  );
}
