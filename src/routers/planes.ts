// src/routers/planes.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z, ZodError } from "zod";

import { db } from "../db";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * =========================================================
 * WELI - PLANES / BENEFICIOS
 * =========================================================
 *
 * Tablas:
 *
 * planes_catalogo
 *   Catálogo GLOBAL de beneficios.
 *
 * plan_reglas
 *   Define cómo se calcula el beneficio.
 *
 * academia_plan
 *   Define qué beneficios están habilitados
 *   para una academia.
 *
 * academia_plan_tipo_pago
 *   Define sobre qué tipos de pago puede
 *   aplicarse un beneficio cuando aplica_todos = 0.
 *
 * academia_tipo_pago
 *   Determina qué tipos de pago están habilitados
 *   realmente para una academia.
 *
 * Seguridad:
 *
 * READ:
 * - Admin       rol 1
 * - Superadmin  rol 3
 *
 * WRITE:
 * - Admin       rol 1
 * - Superadmin  rol 3
 *
 * Scope:
 *
 * Admin:
 * - academia_id proveniente del JWT firmado.
 *
 * Superadmin:
 * - academia_id proveniente de x-academia-id.
 *
 * academia_id NUNCA se acepta desde el body.
 * =========================================================
 */

/* =========================================================
   CONSTANTES
========================================================= */

const MAX_TIPOS_PAGO_BENEFICIO = 100;

/* =========================================================
   SCHEMAS
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const TipoPagoIdSchema = z.coerce.number().int().positive();

const AplicaTodosSchema = z.coerce
  .number()
  .int()
  .refine((value) => value === 0 || value === 1, {
    message: "aplica_todos debe ser 0 o 1",
  });

const CreateSchema = z
  .object({
    /*
     * ID global perteneciente a planes_catalogo.
     */
    plan_id: z.coerce.number().int().positive(),

    /*
     * 1 = beneficio aplicable a todos los tipos de pago
     *     habilitados para la academia.
     *
     * 0 = beneficio aplicable solamente a los tipos
     *     especificados en tipos_pago.
     */
    aplica_todos: AplicaTodosSchema.default(0),

    estado_id: z.coerce.number().int().positive().max(255).default(1),

    /*
     * IDs globales de tipo_pago.
     *
     * Deben estar habilitados previamente para la academia
     * mediante academia_tipo_pago.
     */
    tipos_pago: z.array(TipoPagoIdSchema).max(MAX_TIPOS_PAGO_BENEFICIO).default([]),
  })
  .strict();

const PutSchema = z
  .object({
    plan_id: z.coerce.number().int().positive(),

    aplica_todos: AplicaTodosSchema,

    estado_id: z.coerce.number().int().positive().max(255),

    tipos_pago: z.array(TipoPagoIdSchema).max(MAX_TIPOS_PAGO_BENEFICIO),
  })
  .strict();

const PatchSchema = z
  .object({
    plan_id: z.coerce.number().int().positive().optional(),

    aplica_todos: AplicaTodosSchema.optional(),

    estado_id: z.coerce.number().int().positive().max(255).optional(),

    tipos_pago: z.array(TipoPagoIdSchema).max(MAX_TIPOS_PAGO_BENEFICIO).optional(),
  })
  .strict();

/* =========================================================
   HELPERS GENERALES
========================================================= */

function zodDetail(err: ZodError): string {
  return err.issues.map((issue) => `${issue.path.join(".") || "field"}: ${issue.message}`).join("; ");
}

function businessError(message: string, statusCode = 400) {
  const error: any = new Error(message);

  error.statusCode = statusCode;

  return error;
}

/* =========================================================
   ACADEMIA EFECTIVA
========================================================= */

function resolveAcademiaId(req: FastifyRequest): number {
  const academiaId = Number(getEffectiveAcademiaId(req));

  if (!Number.isInteger(academiaId) || academiaId <= 0) {
    throw businessError("Academia efectiva inválida", 403);
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
     * ID global de planes_catalogo.
     */
    plan_id: Number(row.plan_id),

    nombre: String(row.nombre ?? ""),

    descripcion: row.descripcion == null ? null : String(row.descripcion),

    /*
     * 1 = todos los conceptos habilitados
     * 0 = solamente conceptos específicos
     */
    aplica_todos: Number(row.aplica_todos ?? 0),

    estado_id: Number(row.estado_id),

    catalogo_estado_id: row.catalogo_estado_id == null ? null : Number(row.catalogo_estado_id),

    created_at: row.created_at ?? null,

    updated_at: row.updated_at ?? null,
  };
}

function normalizeTipoPagoIds(values: number[]): number[] {
  return Array.from(new Set((values ?? []).map(Number).filter((id) => Number.isInteger(id) && id > 0)));
}

/* =========================================================
   PLAN GLOBAL
========================================================= */

async function validatePlanGlobal(planId: number, executor: any = db) {
  const [rows]: any = await executor.query(
    `
        SELECT
          id,
          nombre,
          estado_id

        FROM planes_catalogo

        WHERE id = ?

        LIMIT 1
      `,
    [planId]
  );

  if (!rows?.length) {
    throw businessError("El plan no existe en el catálogo global");
  }

  return rows[0];
}

/* =========================================================
   RELACIÓN ACADEMIA_PLAN
========================================================= */

async function getRelacion(academiaId: number, id: number, executor: any = db) {
  const [rows]: any = await executor.query(
    `
        SELECT
          ap.id,
          ap.academia_id,
          ap.plan_id,
          ap.aplica_todos,
          ap.estado_id,

          ap.created_at,
          ap.updated_at,

          pc.nombre,
          pc.descripcion,

          pc.estado_id
            AS catalogo_estado_id

        FROM academia_plan ap

        INNER JOIN planes_catalogo pc
          ON pc.id = ap.plan_id

        WHERE ap.id = ?
          AND ap.academia_id = ?

        LIMIT 1
      `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

async function existsRelation(
  academiaId: number,
  planId: number,
  excludeId?: number,
  executor: any = db
): Promise<boolean> {
  const values: any[] = [academiaId, planId];

  let sql = `
    SELECT
      id

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

  const [rows]: any = await executor.query(sql, values);

  return Array.isArray(rows) && rows.length > 0;
}

/* =========================================================
   REGLAS DEL BENEFICIO
========================================================= */

async function getPlanReglas(planId: number, executor: any = db) {
  const [rows]: any = await executor.query(
    `
        SELECT
          pr.id,
          pr.plan_id,
          pr.tipo_beneficio,
          pr.valor,
          pr.estado_id,
          pr.created_at,
          pr.updated_at

        FROM plan_reglas pr

        WHERE pr.plan_id = ?

        ORDER BY
          pr.id ASC
      `,
    [planId]
  );

  return (rows ?? []).map((row: any) => ({
    id: Number(row.id),

    plan_id: Number(row.plan_id),

    tipo_beneficio: String(row.tipo_beneficio ?? ""),

    valor: Number(row.valor ?? 0),

    estado_id: Number(row.estado_id),

    created_at: row.created_at ?? null,

    updated_at: row.updated_at ?? null,
  }));
}

/* =========================================================
   TIPOS DE PAGO ASOCIADOS AL BENEFICIO
========================================================= */

async function getPlanTiposPago(academiaId: number, academiaPlanId: number, executor: any = db) {
  const [rows]: any = await executor.query(
    `
        SELECT
          aptp.id,
          aptp.academia_id,
          aptp.academia_plan_id,
          aptp.tipo_pago_id,
          aptp.estado_id,
          aptp.created_at,
          aptp.updated_at,

          tp.nombre
            AS tipo_pago_nombre

        FROM academia_plan_tipo_pago aptp

        INNER JOIN tipo_pago tp
          ON tp.id =
             aptp.tipo_pago_id

        WHERE aptp.academia_id = ?
          AND aptp.academia_plan_id = ?
          AND aptp.estado_id = 1

        ORDER BY
          tp.nombre ASC,
          tp.id ASC
      `,
    [academiaId, academiaPlanId]
  );

  return (rows ?? []).map((row: any) => ({
    id: Number(row.id),

    academia_id: Number(row.academia_id),

    academia_plan_id: Number(row.academia_plan_id),

    tipo_pago_id: Number(row.tipo_pago_id),

    nombre: String(row.tipo_pago_nombre ?? ""),

    estado_id: Number(row.estado_id),

    created_at: row.created_at ?? null,

    updated_at: row.updated_at ?? null,
  }));
}

async function getPlanTipoPagoIds(academiaId: number, academiaPlanId: number, executor: any = db): Promise<number[]> {
  const [rows]: any = await executor.query(
    `
        SELECT
          tipo_pago_id

        FROM academia_plan_tipo_pago

        WHERE academia_id = ?
          AND academia_plan_id = ?
          AND estado_id = 1

        ORDER BY
          tipo_pago_id ASC
      `,
    [academiaId, academiaPlanId]
  );

  return normalizeTipoPagoIds((rows ?? []).map((row: any) => Number(row.tipo_pago_id)));
}

/* =========================================================
   VALIDACIÓN DEL ALCANCE DEL BENEFICIO
========================================================= */

function validateAplicacionBeneficio(aplicaTodos: number, tiposPago: number[]) {
  const ids = normalizeTipoPagoIds(tiposPago);

  if (aplicaTodos === 1) {
    if (ids.length > 0) {
      throw businessError("Si aplica_todos es 1, no debes enviar tipos de pago específicos");
    }

    return;
  }

  if (aplicaTodos === 0) {
    if (!ids.length) {
      throw businessError("Debes seleccionar al menos un tipo de pago cuando aplica_todos es 0");
    }

    return;
  }

  throw businessError("aplica_todos debe ser 0 o 1");
}

/* =========================================================
   VALIDAR TIPOS DE PAGO DE LA ACADEMIA
========================================================= */

async function validateTiposPagoAcademia(academiaId: number, tiposPagoIds: number[], executor: any = db) {
  const ids = normalizeTipoPagoIds(tiposPagoIds);

  if (!ids.length) {
    return;
  }

  const placeholders = ids.map(() => "?").join(", ");

  const [rows]: any = await executor.query(
    `
        SELECT
          atp.tipo_pago_id

        FROM academia_tipo_pago atp

        INNER JOIN tipo_pago tp
          ON tp.id =
             atp.tipo_pago_id

        WHERE atp.academia_id = ?

          AND atp.tipo_pago_id
            IN (${placeholders})

          AND atp.estado_id = 1

          AND tp.estado_id = 1
      `,
    [academiaId, ...ids]
  );

  const validIds = new Set((rows ?? []).map((row: any) => Number(row.tipo_pago_id)));

  const invalidIds = ids.filter((id) => !validIds.has(id));

  if (invalidIds.length) {
    throw businessError(`Uno o más tipos de pago no están habilitados para esta academia: ${invalidIds.join(", ")}`);
  }
}

/* =========================================================
   REEMPLAZAR TIPOS DE PAGO
========================================================= */

async function replacePlanTiposPago(
  executor: any,
  academiaId: number,
  academiaPlanId: number,
  aplicaTodos: number,
  tiposPagoIds: number[]
) {
  /*
   * Primero eliminamos el estado anterior.
   *
   * academia_plan_tipo_pago representa
   * la configuración actual del beneficio.
   */
  await executor.query(
    `
      DELETE
      FROM academia_plan_tipo_pago

      WHERE academia_id = ?
        AND academia_plan_id = ?
    `,
    [academiaId, academiaPlanId]
  );

  /*
   * Si aplica a todos, no necesitamos
   * registros específicos.
   */
  if (aplicaTodos === 1) {
    return;
  }

  const ids = normalizeTipoPagoIds(tiposPagoIds);

  for (const tipoPagoId of ids) {
    await executor.query(
      `
        INSERT INTO academia_plan_tipo_pago (
          academia_id,
          academia_plan_id,
          tipo_pago_id,
          estado_id
        )

        VALUES (?, ?, ?, 1)
      `,
      [academiaId, academiaPlanId, tipoPagoId]
    );
  }
}

/* =========================================================
   CONSTRUIR RESPUESTA DE BENEFICIO
========================================================= */

async function buildPlanItem(academiaId: number, row: any, executor: any = db) {
  const item = normalize(row);

  const reglas = await getPlanReglas(item.plan_id, executor);

  /*
   * Cuando aplica_todos = 1,
   * el arreglo específico queda vacío.
   */
  const tipos_pago = item.aplica_todos === 1 ? [] : await getPlanTiposPago(academiaId, item.id, executor);

  return {
    ...item,

    reglas,

    tipos_pago,
  };
}

/* =========================================================
   DEPENDENCIAS
========================================================= */

/**
 * Si una academia ya utilizó el beneficio para:
 *
 * - asignarlo a un jugador
 * - registrar un pago
 *
 * no permitimos transformar esa relación
 * hacia otro plan global ni eliminarla.
 *
 * Desactivar sigue siendo permitido.
 */

async function relationHasDependencies(
  academiaId: number,
  planId: number,
  executor: any = db
): Promise<{
  used: boolean;
  source: string | null;
}> {
  /* -------------------------------------------------------
     BENEFICIO ASIGNADO A JUGADOR
  ------------------------------------------------------- */

  const [jugadores]: any = await executor.query(
    `
        SELECT
          id

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
     BENEFICIO REGISTRADO EN PAGOS
  ------------------------------------------------------- */

  const [pagos]: any = await executor.query(
    `
        SELECT
          id

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
   MANEJO DE ERRORES
========================================================= */

function scopeError(reply: FastifyReply, err: any) {
  const status = Number(err?.statusCode ?? 0);

  if (status === 400 || status === 401 || status === 403 || status === 404 || status === 409) {
    reply.header("Cache-Control", "no-store");

    return reply.code(status).send({
      ok: false,

      message: err?.message || "No fue posible procesar la solicitud",
    });
  }

  return null;
}

/* =========================================================
   ROUTER
========================================================= */

export default async function planes(app: FastifyInstance) {
  /*
   * Configuración económica:
   *
   * Staff NO administra beneficios.
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

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     GET /
     BENEFICIOS HABILITADOS PARA LA ACADEMIA
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
                ap.aplica_todos,
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
          items.push(await buildPlanItem(academiaId, row));
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
     CATÁLOGO GLOBAL DE BENEFICIOS
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

        const item = await buildPlanItem(academiaId, row);

        return reply.send({
          ok: true,

          item,
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
     HABILITAR BENEFICIO EN ACADEMIA
  ======================================================= */

  app.post(
    "/",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      let conn: any = null;

      try {
        const academiaId = resolveAcademiaId(req);

        const body = CreateSchema.parse(req.body);

        const planId = Number(body.plan_id);

        const aplicaTodos = Number(body.aplica_todos);

        const estadoId = Number(body.estado_id);

        const tiposPago = normalizeTipoPagoIds(body.tipos_pago);

        validateAplicacionBeneficio(aplicaTodos, tiposPago);

        conn = await db.getConnection();

        await conn.beginTransaction();

        await validatePlanGlobal(planId, conn);

        const duplicate = await existsRelation(academiaId, planId, undefined, conn);

        if (duplicate) {
          throw businessError("Este plan ya se encuentra asociado a la academia", 409);
        }

        if (aplicaTodos === 0) {
          await validateTiposPagoAcademia(academiaId, tiposPago, conn);
        }

        const [result]: any = await conn.query(
          `
              INSERT INTO academia_plan (
                academia_id,
                plan_id,
                aplica_todos,
                estado_id
              )

              VALUES (?, ?, ?, ?)
            `,
          [academiaId, planId, aplicaTodos, estadoId]
        );

        const insertId = Number(result?.insertId);

        if (!Number.isInteger(insertId) || insertId <= 0) {
          throw new Error("No fue posible obtener el ID de la asociación creada");
        }

        await replacePlanTiposPago(conn, academiaId, insertId, aplicaTodos, tiposPago);

        const row = await getRelacion(academiaId, insertId, conn);

        if (!row) {
          throw new Error("No fue posible recuperar el beneficio creado");
        }

        const item = await buildPlanItem(academiaId, row, conn);

        await conn.commit();

        reply.header("Cache-Control", "no-store");

        return reply.code(201).send({
          ok: true,

          id: insertId,

          item,
        });
      } catch (err: any) {
        if (conn) {
          try {
            await conn.rollback();
          } catch {}
        }

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

            message: "Uno de los registros relacionados no existe",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al asociar plan con academia",

          detail: err?.message,
        });
      } finally {
        if (conn) {
          conn.release();
        }
      }
    }
  );

  /* =======================================================
     PUT /:id
     REEMPLAZO COMPLETO
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

      let conn: any = null;

      try {
        const academiaId = resolveAcademiaId(req);

        const id = parsedId.data.id;

        const body = PutSchema.parse(req.body);

        const planId = Number(body.plan_id);

        const aplicaTodos = Number(body.aplica_todos);

        const estadoId = Number(body.estado_id);

        const tiposPago = normalizeTipoPagoIds(body.tipos_pago);

        validateAplicacionBeneficio(aplicaTodos, tiposPago);

        conn = await db.getConnection();

        await conn.beginTransaction();

        const current = await getRelacion(academiaId, id, conn);

        if (!current) {
          throw businessError("Plan no encontrado", 404);
        }

        const changingPlan = planId !== Number(current.plan_id);

        if (changingPlan) {
          const dependencies = await relationHasDependencies(academiaId, Number(current.plan_id), conn);

          if (dependencies.used) {
            throw businessError(
              "La asociación actual está siendo utilizada y no puede cambiarse a otro plan. Puede desactivarse mediante estado_id",
              409
            );
          }
        }

        await validatePlanGlobal(planId, conn);

        const duplicate = await existsRelation(academiaId, planId, id, conn);

        if (duplicate) {
          throw businessError("Ya existe otra asociación de esta academia con ese plan", 409);
        }

        if (aplicaTodos === 0) {
          await validateTiposPagoAcademia(academiaId, tiposPago, conn);
        }

        const [result]: any = await conn.query(
          `
              UPDATE academia_plan

              SET
                plan_id = ?,
                aplica_todos = ?,
                estado_id = ?

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [planId, aplicaTodos, estadoId, id, academiaId]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          throw businessError("Plan no encontrado", 404);
        }

        await replacePlanTiposPago(conn, academiaId, id, aplicaTodos, tiposPago);

        const row = await getRelacion(academiaId, id, conn);

        if (!row) {
          throw new Error("No fue posible recuperar el plan actualizado");
        }

        const updated = await buildPlanItem(academiaId, row, conn);

        await conn.commit();

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          updated,
        });
      } catch (err: any) {
        if (conn) {
          try {
            await conn.rollback();
          } catch {}
        }

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

            message: "Uno de los registros relacionados no existe",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al actualizar plan",

          detail: err?.message,
        });
      } finally {
        if (conn) {
          conn.release();
        }
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

      let conn: any = null;

      try {
        const academiaId = resolveAcademiaId(req);

        const id = parsedId.data.id;

        const body = PatchSchema.parse(req.body);

        if (Object.keys(body).length === 0) {
          throw businessError("No hay campos para actualizar");
        }

        conn = await db.getConnection();

        await conn.beginTransaction();

        const current = await getRelacion(academiaId, id, conn);

        if (!current) {
          throw businessError("Plan no encontrado", 404);
        }

        const currentTiposPago = await getPlanTipoPagoIds(academiaId, id, conn);

        const planId = body.plan_id !== undefined ? Number(body.plan_id) : Number(current.plan_id);

        const aplicaTodos = body.aplica_todos !== undefined ? Number(body.aplica_todos) : Number(current.aplica_todos);

        const estadoId = body.estado_id !== undefined ? Number(body.estado_id) : Number(current.estado_id);

        const tiposPago =
          body.tipos_pago !== undefined
            ? normalizeTipoPagoIds(body.tipos_pago)
            : aplicaTodos === 1
              ? []
              : currentTiposPago;

        validateAplicacionBeneficio(aplicaTodos, tiposPago);

        const changingPlan = planId !== Number(current.plan_id);

        if (changingPlan) {
          const dependencies = await relationHasDependencies(academiaId, Number(current.plan_id), conn);

          if (dependencies.used) {
            throw businessError(
              "La asociación actual está siendo utilizada y no puede cambiarse a otro plan. Puede desactivarse mediante estado_id",
              409
            );
          }

          await validatePlanGlobal(planId, conn);

          const duplicate = await existsRelation(academiaId, planId, id, conn);

          if (duplicate) {
            throw businessError("Ya existe otra asociación de esta academia con ese plan", 409);
          }
        }

        /*
         * Aunque PATCH no cambie plan_id,
         * si cambia el alcance debemos comprobar
         * los tipos de pago resultantes.
         */
        if (aplicaTodos === 0) {
          await validateTiposPagoAcademia(academiaId, tiposPago, conn);
        }

        const [result]: any = await conn.query(
          `
              UPDATE academia_plan

              SET
                plan_id = ?,
                aplica_todos = ?,
                estado_id = ?

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [planId, aplicaTodos, estadoId, id, academiaId]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          throw businessError("Plan no encontrado", 404);
        }

        /*
         * Solo reconstruimos el scope cuando
         * PATCH modifica aplica_todos o tipos_pago.
         *
         * Si únicamente cambia nombre lógico
         * del plan o estado, conservamos asociaciones.
         */
        if (body.aplica_todos !== undefined || body.tipos_pago !== undefined) {
          await replacePlanTiposPago(conn, academiaId, id, aplicaTodos, tiposPago);
        }

        const row = await getRelacion(academiaId, id, conn);

        if (!row) {
          throw new Error("No fue posible recuperar el plan actualizado");
        }

        const updated = await buildPlanItem(academiaId, row, conn);

        await conn.commit();

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          updated,
        });
      } catch (err: any) {
        if (conn) {
          try {
            await conn.rollback();
          } catch {}
        }

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

            message: "Uno de los registros relacionados no existe",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al actualizar plan",

          detail: err?.message,
        });
      } finally {
        if (conn) {
          conn.release();
        }
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

      let conn: any = null;

      try {
        const academiaId = resolveAcademiaId(req);

        const id = parsed.data.id;

        conn = await db.getConnection();

        await conn.beginTransaction();

        const current = await getRelacion(academiaId, id, conn);

        if (!current) {
          throw businessError("Plan no encontrado", 404);
        }

        const dependencies = await relationHasDependencies(academiaId, Number(current.plan_id), conn);

        if (dependencies.used) {
          throw businessError(
            "El plan está siendo utilizado por jugadores o pagos y no puede eliminarse de la academia. Debe desactivarse mediante estado_id",
            409
          );
        }

        /*
         * academia_plan_tipo_pago tiene FK RESTRICT,
         * por lo que eliminamos explícitamente
         * las asociaciones antes del padre.
         */
        await conn.query(
          `
            DELETE
            FROM academia_plan_tipo_pago

            WHERE academia_id = ?
              AND academia_plan_id = ?
          `,
          [academiaId, id]
        );

        const [result]: any = await conn.query(
          `
              DELETE
              FROM academia_plan

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [id, academiaId]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          throw businessError("Plan no encontrado", 404);
        }

        await conn.commit();

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          deleted: id,
        });
      } catch (err: any) {
        if (conn) {
          try {
            await conn.rollback();
          } catch {}
        }

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
      } finally {
        if (conn) {
          conn.release();
        }
      }
    }
  );
}
