// src/routers/academia_tipo_pago.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z, ZodError } from "zod";

import { db } from "../db";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * =========================================================
 * WELI - TIPOS DE PAGO POR ACADEMIA
 * =========================================================
 *
 * Tabla principal:
 *
 * academia_tipo_pago
 *
 * Modelo:
 *
 * tipo_pago
 *      │
 *      ▼
 * academia_tipo_pago
 *      │
 *      ├──────────────► tarifas_academia
 *      │
 *      └──────────────► academia_plan_tipo_pago
 *
 * pago_detalle conserva posteriormente
 * la trazabilidad histórica del concepto.
 *
 * Scope:
 *
 * Multi-academia.
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
 * Staff:
 * - sin acceso.
 *
 * academia_id:
 *
 * Admin:
 * - academia firmada en JWT.
 *
 * Superadmin:
 * - x-academia-id validado por authz.
 *
 * academia_id NUNCA se recibe
 * desde el body.
 *
 * Reglas:
 *
 * - tipo_pago_id referencia catálogo GLOBAL tipo_pago.
 *
 * - una academia no puede relacionar dos veces
 *   el mismo tipo_pago_id.
 *
 * - estado_id = 1 significa concepto habilitado.
 *
 * - deshabilitar una relación NO elimina
 *   el concepto global.
 *
 * - el precio pertenece a tarifas_academia.
 *
 * - no se cambia tipo_pago_id ni se elimina
 *   una relación cuando tiene tarifa,
 *   historial financiero o configuración
 *   de beneficios asociada.
 *
 * - un tipo_pago global inactivo no puede
 *   habilitarse en una academia.
 * =========================================================
 */

/* =========================================================
   CONSTANTES
========================================================= */

const ESTADO_ACTIVO = 1;

/* =========================================================
   SCHEMAS
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const EstadoSchema = z.coerce.number().int().positive().max(255);

const CreateSchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive(),

    estado_id: EstadoSchema.default(ESTADO_ACTIVO),
  })
  .strict();

const PutSchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive(),

    estado_id: EstadoSchema,
  })
  .strict();

const PatchSchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive().optional(),

    estado_id: EstadoSchema.optional(),
  })
  .strict();

const QuerySchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive().optional(),

    estado_id: EstadoSchema.optional(),

    limit: z.coerce.number().int().min(1).max(500).default(200),
  })
  .strict();

/* =========================================================
   HELPERS GENERALES
========================================================= */

function zodDetail(err: ZodError): string {
  return err.issues.map((issue) => `${issue.path.join(".") || "field"}: ${issue.message}`).join("; ");
}

function businessError(message: string, statusCode = 400): never {
  const err: any = new Error(message);

  err.statusCode = statusCode;

  throw err;
}

/* =========================================================
   ACADEMIA EFECTIVA
========================================================= */

function resolveAcademiaId(req: FastifyRequest): number {
  const academiaId = Number(getEffectiveAcademiaId(req));

  if (!Number.isInteger(academiaId) || academiaId <= 0) {
    businessError("Academia efectiva inválida", 403);
  }

  return academiaId;
}

/* =========================================================
   NORMALIZACIÓN
========================================================= */

function normalize(row: any) {
  return {
    /*
     * ID de academia_tipo_pago.
     */
    id: Number(row.id),

    academia_id: Number(row.academia_id),

    /*
     * ID global de tipo_pago.
     */
    tipo_pago_id: Number(row.tipo_pago_id),

    /*
     * Estado de la relación academia-tipo.
     */
    estado_id: Number(row.estado_id),

    tipo_pago_nombre: row.tipo_pago_nombre == null ? undefined : String(row.tipo_pago_nombre),

    tipo_pago_descripcion: row.tipo_pago_descripcion == null ? null : String(row.tipo_pago_descripcion),

    /*
     * Estado del catálogo global.
     */
    tipo_pago_estado_id: row.tipo_pago_estado_id == null ? undefined : Number(row.tipo_pago_estado_id),

    /*
     * Tarifa actual de la academia.
     */
    tarifa_id: row.tarifa_id == null ? null : Number(row.tarifa_id),

    monto: row.monto == null ? null : Number(row.monto),

    tarifa_estado_id: row.tarifa_estado_id == null ? null : Number(row.tarifa_estado_id),

    created_at: row.created_at ?? null,

    updated_at: row.updated_at ?? null,
  };
}

/* =========================================================
   OBTENER RELACIÓN
========================================================= */

async function getRelacion(academiaId: number, id: number, executor: any = db) {
  const [rows]: any = await executor.query(
    `
        SELECT
          atp.id,
          atp.academia_id,
          atp.tipo_pago_id,
          atp.estado_id,
          atp.created_at,
          atp.updated_at,

          tp.nombre
            AS tipo_pago_nombre,

          tp.descripcion
            AS tipo_pago_descripcion,

          tp.estado_id
            AS tipo_pago_estado_id,

          ta.id
            AS tarifa_id,

          ta.monto,

          ta.estado_id
            AS tarifa_estado_id

        FROM academia_tipo_pago atp

        INNER JOIN tipo_pago tp
          ON tp.id =
             atp.tipo_pago_id

        LEFT JOIN tarifas_academia ta
          ON ta.academia_id =
             atp.academia_id

         AND ta.tipo_pago_id =
             atp.tipo_pago_id

        WHERE atp.id = ?
          AND atp.academia_id = ?

        LIMIT 1
      `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

/* =========================================================
   VALIDAR CATÁLOGO GLOBAL
========================================================= */

/**
 * Devuelve el concepto global.
 *
 * requireActive=true:
 * el concepto además debe encontrarse activo.
 */

async function validateTipoPagoGlobal(tipoPagoId: number, requireActive = false, executor: any = db) {
  const [rows]: any = await executor.query(
    `
        SELECT
          id,
          nombre,
          estado_id

        FROM tipo_pago

        WHERE id = ?

        LIMIT 1
      `,
    [tipoPagoId]
  );

  if (!rows?.length) {
    businessError("El tipo de pago no existe en el catálogo global");
  }

  const row = rows[0];

  if (requireActive && Number(row.estado_id) !== ESTADO_ACTIVO) {
    businessError("El tipo de pago no se encuentra activo en el catálogo global");
  }

  return row;
}

/* =========================================================
   DUPLICIDAD DE RELACIÓN
========================================================= */

async function existsRelation(
  academiaId: number,
  tipoPagoId: number,
  excludeId?: number,
  executor: any = db
): Promise<boolean> {
  const values: any[] = [academiaId, tipoPagoId];

  let sql = `
    SELECT
      id

    FROM academia_tipo_pago

    WHERE academia_id = ?
      AND tipo_pago_id = ?
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
   DEPENDENCIAS
========================================================= */

/**
 * Una relación academia_tipo_pago no puede
 * cambiar de identidad ni eliminarse cuando
 * existe información dependiente.
 *
 * Revisamos:
 *
 * 1. tarifas_academia
 * 2. pago_detalle + pagos_jugador
 * 3. academia_plan_tipo_pago
 */

async function relationHasDependencies(
  academiaId: number,
  tipoPagoId: number,
  executor: any = db
): Promise<{
  used: boolean;
  source: string | null;
}> {
  /* -------------------------------------------------------
     TARIFA DE LA ACADEMIA
  ------------------------------------------------------- */

  const [tarifas]: any = await executor.query(
    `
        SELECT
          id

        FROM tarifas_academia

        WHERE academia_id = ?
          AND tipo_pago_id = ?

        LIMIT 1
      `,
    [academiaId, tipoPagoId]
  );

  if (tarifas?.length) {
    return {
      used: true,
      source: "tarifas_academia",
    };
  }

  /* -------------------------------------------------------
     CONFIGURACIÓN DE BENEFICIO
  ------------------------------------------------------- */

  const [beneficios]: any = await executor.query(
    `
        SELECT
          id

        FROM academia_plan_tipo_pago

        WHERE academia_id = ?
          AND tipo_pago_id = ?

        LIMIT 1
      `,
    [academiaId, tipoPagoId]
  );

  if (beneficios?.length) {
    return {
      used: true,
      source: "academia_plan_tipo_pago",
    };
  }

  /* -------------------------------------------------------
     HISTORIAL DE PAGOS
  ------------------------------------------------------- */

  const [pagos]: any = await executor.query(
    `
        SELECT
          pd.id

        FROM pago_detalle pd

        INNER JOIN pagos_jugador p
          ON p.id =
             pd.pago_id

        WHERE p.academia_id = ?
          AND pd.tipo_pago_id = ?

        LIMIT 1
      `,
    [academiaId, tipoPagoId]
  );

  if (pagos?.length) {
    return {
      used: true,
      source: "pago_detalle",
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

function handleKnownError(reply: FastifyReply, err: any) {
  const status = Number(err?.statusCode ?? 0);

  if ([400, 401, 403, 404, 409].includes(status)) {
    reply.header("Cache-Control", "no-store");

    return reply.code(status).send({
      ok: false,

      message: err?.message ?? "No fue posible procesar la solicitud",
    });
  }

  return null;
}

/* =========================================================
   ROUTER
========================================================= */

export default async function academia_tipo_pago(app: FastifyInstance) {
  /*
   * Configuración financiera.
   *
   * Admin:
   * - lectura y administración
   *   de su academia.
   *
   * Superadmin:
   * - lectura y administración
   *   de academia seleccionada.
   *
   * Staff:
   * - sin acceso.
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
          module: "academia_tipo_pago",

          status: "ready",

          academia_id: academiaId,

          timestamp: new Date().toISOString(),
        });
      } catch (err: any) {
        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        reply.header("Cache-Control", "no-store");

        return reply.code(500).send({
          ok: false,

          message: "Error en módulo academia_tipo_pago",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     GET /
     CONFIGURACIÓN DE TIPOS DE PAGO DE LA ACADEMIA

     IMPORTANTE:
     esta ruta puede devolver activos e inactivos,
     porque corresponde al módulo administrativo.
  ======================================================= */

  app.get(
    "/",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const academiaId = resolveAcademiaId(req);

        const query = QuerySchema.parse(req.query);

        const where: string[] = ["atp.academia_id = ?"];

        const values: any[] = [academiaId];

        if (query.tipo_pago_id !== undefined) {
          where.push("atp.tipo_pago_id = ?");

          values.push(query.tipo_pago_id);
        }

        if (query.estado_id !== undefined) {
          where.push("atp.estado_id = ?");

          values.push(query.estado_id);
        }

        values.push(query.limit);

        const [rows]: any = await db.query(
          `
              SELECT
                atp.id,
                atp.academia_id,
                atp.tipo_pago_id,
                atp.estado_id,
                atp.created_at,
                atp.updated_at,

                tp.nombre
                  AS tipo_pago_nombre,

                tp.descripcion
                  AS tipo_pago_descripcion,

                tp.estado_id
                  AS tipo_pago_estado_id,

                ta.id
                  AS tarifa_id,

                ta.monto,

                ta.estado_id
                  AS tarifa_estado_id

              FROM academia_tipo_pago atp

              INNER JOIN tipo_pago tp
                ON tp.id =
                   atp.tipo_pago_id

              LEFT JOIN tarifas_academia ta
                ON ta.academia_id =
                   atp.academia_id

               AND ta.tipo_pago_id =
                   atp.tipo_pago_id

              WHERE
                ${where.join(" AND ")}

              ORDER BY
                atp.estado_id ASC,
                tp.nombre ASC,
                atp.id ASC

              LIMIT ?
            `,
          values
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          academia_id: academiaId,

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

        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al listar tipos de pago de la academia",

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

        const row = await getRelacion(academiaId, parsed.data.id);

        reply.header("Cache-Control", "no-store");

        if (!row) {
          return reply.code(404).send({
            ok: false,

            message: "Relación academia-tipo de pago no encontrada",
          });
        }

        return reply.send({
          ok: true,

          academia_id: academiaId,

          item: normalize(row),
        });
      } catch (err: any) {
        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        reply.header("Cache-Control", "no-store");

        return reply.code(500).send({
          ok: false,

          message: "Error al obtener tipo de pago de la academia",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     POST /
     HABILITAR CONCEPTO EN ACADEMIA
  ======================================================= */

  app.post(
    "/",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const academiaId = resolveAcademiaId(req);

        const body = CreateSchema.parse(req.body);

        /*
         * Si se crea habilitado,
         * el catálogo global debe estar activo.
         *
         * Si se crea deshabilitado,
         * basta con que exista.
         */
        await validateTipoPagoGlobal(body.tipo_pago_id, Number(body.estado_id) === ESTADO_ACTIVO);

        const duplicate = await existsRelation(academiaId, body.tipo_pago_id);

        if (duplicate) {
          businessError("Este tipo de pago ya se encuentra asociado a la academia", 409);
        }

        const [result]: any = await db.query(
          `
              INSERT INTO academia_tipo_pago (
                academia_id,
                tipo_pago_id,
                estado_id
              )

              VALUES (?, ?, ?)
            `,
          [academiaId, body.tipo_pago_id, body.estado_id]
        );

        const insertId = Number(result?.insertId);

        if (!Number.isInteger(insertId) || insertId <= 0) {
          throw new Error("No fue posible obtener el ID de la relación creada");
        }

        const row = await getRelacion(academiaId, insertId);

        reply.header("Cache-Control", "no-store");

        return reply.code(201).send({
          ok: true,

          id: insertId,

          item: row
            ? normalize(row)
            : {
                id: insertId,

                academia_id: academiaId,

                tipo_pago_id: body.tipo_pago_id,

                estado_id: body.estado_id,

                tarifa_id: null,

                monto: null,

                tarifa_estado_id: null,
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

        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "Este tipo de pago ya se encuentra asociado a la academia",
          });
        }

        if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
          return reply.code(409).send({
            ok: false,

            message: "La academia o el tipo de pago indicado no existe",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al asociar tipo de pago con academia",

          detail: err?.message,
        });
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
          businessError("Relación academia-tipo de pago no encontrada", 404);
        }

        const body = PutSchema.parse(req.body);

        const changingTipoPago = Number(body.tipo_pago_id) !== Number(current.tipo_pago_id);

        /*
         * Cambiar tipo_pago_id altera
         * la identidad de la relación.
         */
        if (changingTipoPago) {
          const dependencies = await relationHasDependencies(academiaId, Number(current.tipo_pago_id));

          if (dependencies.used) {
            businessError(
              "La asociación actual posee tarifa, configuración de beneficio o historial financiero y no puede cambiar de tipo de pago",
              409
            );
          }
        }

        /*
         * Si el estado resultante será activo,
         * el tipo global debe estar activo.
         */
        await validateTipoPagoGlobal(body.tipo_pago_id, Number(body.estado_id) === ESTADO_ACTIVO);

        const duplicate = await existsRelation(academiaId, body.tipo_pago_id, id);

        if (duplicate) {
          businessError("Ya existe otra asociación de esta academia con ese tipo de pago", 409);
        }

        const [result]: any = await db.query(
          `
              UPDATE academia_tipo_pago

              SET
                tipo_pago_id = ?,
                estado_id = ?

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [body.tipo_pago_id, body.estado_id, id, academiaId]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          businessError("Relación academia-tipo de pago no encontrada", 404);
        }

        const updated = await getRelacion(academiaId, id);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          updated: updated
            ? normalize(updated)
            : {
                id,

                academia_id: academiaId,

                tipo_pago_id: body.tipo_pago_id,

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

        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "Ya existe otra asociación de esta academia con ese tipo de pago",
          });
        }

        if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
          return reply.code(409).send({
            ok: false,

            message: "La academia o el tipo de pago indicado no existe",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al actualizar tipo de pago de academia",

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
          businessError("Relación academia-tipo de pago no encontrada", 404);
        }

        const body = PatchSchema.parse(req.body);

        if (Object.keys(body).length === 0) {
          businessError("No hay campos para actualizar");
        }

        const tipoPagoId = body.tipo_pago_id !== undefined ? Number(body.tipo_pago_id) : Number(current.tipo_pago_id);

        const estadoId = body.estado_id !== undefined ? Number(body.estado_id) : Number(current.estado_id);

        const changingTipoPago = tipoPagoId !== Number(current.tipo_pago_id);

        if (changingTipoPago) {
          const dependencies = await relationHasDependencies(academiaId, Number(current.tipo_pago_id));

          if (dependencies.used) {
            businessError(
              "La asociación actual posee tarifa, configuración de beneficio o historial financiero y no puede cambiar de tipo de pago",
              409
            );
          }
        }

        /*
         * Si la relación resultante estará activa,
         * el catálogo global también debe estar activo.
         */
        await validateTipoPagoGlobal(tipoPagoId, estadoId === ESTADO_ACTIVO);

        const duplicate = await existsRelation(academiaId, tipoPagoId, id);

        if (duplicate) {
          businessError("Ya existe otra asociación de esta academia con ese tipo de pago", 409);
        }

        const [result]: any = await db.query(
          `
              UPDATE academia_tipo_pago

              SET
                tipo_pago_id = ?,
                estado_id = ?

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [tipoPagoId, estadoId, id, academiaId]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          businessError("Relación academia-tipo de pago no encontrada", 404);
        }

        const updated = await getRelacion(academiaId, id);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          updated: updated
            ? normalize(updated)
            : {
                id,

                academia_id: academiaId,

                tipo_pago_id: tipoPagoId,

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

        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "Ya existe otra asociación de esta academia con ese tipo de pago",
          });
        }

        if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
          return reply.code(409).send({
            ok: false,

            message: "La academia o el tipo de pago indicado no existe",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al actualizar tipo de pago de academia",

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
          businessError("Relación academia-tipo de pago no encontrada", 404);
        }

        const dependencies = await relationHasDependencies(academiaId, Number(current.tipo_pago_id));

        if (dependencies.used) {
          let message =
            "El tipo de pago posee información relacionada y no puede eliminarse. Debe desactivarse mediante estado_id";

          if (dependencies.source === "tarifas_academia") {
            message =
              "El tipo de pago posee una tarifa configurada y no puede eliminarse. Debe desactivarse mediante estado_id";
          }

          if (dependencies.source === "academia_plan_tipo_pago") {
            message =
              "El tipo de pago está siendo utilizado por uno o más beneficios de la academia y no puede eliminarse. Debe desactivarse o quitarse primero de la configuración de beneficios";
          }

          if (dependencies.source === "pago_detalle") {
            message =
              "El tipo de pago posee historial financiero y no puede eliminarse. Debe desactivarse mediante estado_id";
          }

          businessError(message, 409);
        }

        const [result]: any = await db.query(
          `
              DELETE
              FROM academia_tipo_pago

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [id, academiaId]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          businessError("Relación academia-tipo de pago no encontrada", 404);
        }

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          academia_id: academiaId,

          deleted: id,
        });
      } catch (err: any) {
        reply.header("Cache-Control", "no-store");

        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1451 || String(err?.code ?? "").includes("ER_ROW_IS_REFERENCED")) {
          return reply.code(409).send({
            ok: false,

            message: "No se puede eliminar la asociación porque posee información relacionada",

            detail: err?.sqlMessage ?? err?.message,
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al eliminar tipo de pago de academia",

          detail: err?.message,
        });
      }
    }
  );
}
