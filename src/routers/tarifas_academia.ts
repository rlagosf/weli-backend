// src/routes/routers/tarifas_academia.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z, ZodError } from "zod";

import { db } from "../db";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * ============================================================
 * WELI - TARIFAS POR ACADEMIA
 * ============================================================
 *
 * Tabla:
 *
 * tarifas_academia
 *
 * Responsabilidad:
 *
 * Cada academia define cuánto cobra por cada tipo de pago
 * previamente habilitado mediante academia_tipo_pago.
 *
 *
 * MODELO HISTÓRICO
 * ------------------------------------------------------------
 *
 * Una modificación de precio NO sobrescribe la tarifa anterior.
 *
 * Ejemplo:
 *
 *  Mantención:
 *
 *  $20.000
 *  2026-01-01 -> 2026-09-16
 *  es_vigente = NULL
 *
 *  $25.000
 *  2026-09-16 -> NULL
 *  es_vigente = 1
 *
 *
 * Regla:
 *
 * - es_vigente = 1
 *      tarifa actual.
 *
 * - es_vigente = NULL
 *      tarifa histórica.
 *
 * Solo puede existir UNA tarifa vigente por:
 *
 *   academia_id + tipo_pago_id
 *
 * mediante:
 *
 * uq_tarifa_vigente_academia_tipo
 *
 *
 * TRAZABILIDAD
 * ------------------------------------------------------------
 *
 * pago_detalle.tarifa_id apunta a la versión exacta
 * de tarifa utilizada al momento del cobro.
 *
 * Por tanto:
 *
 * - nunca modificamos el monto de una tarifa histórica;
 * - cambiar precio crea una nueva versión;
 * - el historial permanece disponible.
 *
 *
 * SEGURIDAD
 * ------------------------------------------------------------
 *
 * Roles:
 *
 * Admin      = 1
 * Superadmin = 3
 *
 * academia_id:
 *
 * Admin:
 * - proviene del JWT.
 *
 * Superadmin:
 * - proviene de x-academia-id.
 *
 * academia_id NUNCA se recibe desde el body.
 * ============================================================
 */

/* ============================================================
   SCHEMAS
============================================================ */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const EstadoSchema = z.coerce.number().int().min(0).max(1);

const MontoSchema = z.coerce.number().finite().nonnegative().max(99999999.99);

/*
 * Crear una tarifa significa crear
 * la tarifa VIGENTE.
 */
const CreateSchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive(),

    monto: MontoSchema,

    /*
     * Se mantiene por compatibilidad.
     *
     * Una tarifa nueva debe quedar activa.
     */
    estado_id: EstadoSchema.default(1),
  })
  .strict();

/*
 * PUT:
 *
 * Permitimos recibir tipo_pago_id por compatibilidad
 * con clientes existentes, pero NO permitiremos cambiarlo.
 *
 * La identidad histórica de la tarifa debe mantenerse.
 */
const PutSchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive(),

    monto: MontoSchema,

    estado_id: EstadoSchema.default(1),
  })
  .strict();

/*
 * PATCH:
 *
 * - monto:
 *     genera nueva versión si cambia.
 *
 * - estado_id = 0:
 *     cierra la tarifa vigente.
 *
 * - tipo_pago_id:
 *     se acepta por compatibilidad,
 *     pero no puede cambiar respecto de la tarifa.
 */
const PatchSchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive().optional(),

    monto: MontoSchema.optional(),

    estado_id: EstadoSchema.optional(),
  })
  .strict();

const QuerySchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive().optional(),

    estado_id: EstadoSchema.optional(),

    /*
     * 0:
     *   solo tarifas vigentes.
     *
     * 1:
     *   incluye historial.
     */
    incluir_historial: z
      .enum(["0", "1"])
      .default("0")
      .transform((value) => value === "1"),

    limit: z.coerce.number().int().min(1).max(500).default(200),
  })
  .strict();

/* ============================================================
   HELPERS GENERALES
============================================================ */

function zodDetail(err: ZodError): string {
  return err.issues.map((issue) => `${issue.path.join(".") || "field"}: ${issue.message}`).join("; ");
}

function makeHttpError(statusCode: number, message: string) {
  const err: any = new Error(message);

  err.statusCode = statusCode;

  return err;
}

/* ============================================================
   ACADEMIA EFECTIVA
============================================================ */

function resolveAcademiaId(req: FastifyRequest): number {
  const academiaId = Number(getEffectiveAcademiaId(req));

  if (!Number.isInteger(academiaId) || academiaId <= 0) {
    throw makeHttpError(403, "Academia efectiva inválida");
  }

  return academiaId;
}

/* ============================================================
   NORMALIZACIÓN
============================================================ */

function normalize(row: any) {
  return {
    id: Number(row.id),

    academia_id: Number(row.academia_id),

    tipo_pago_id: Number(row.tipo_pago_id),

    tipo_pago_nombre: row.tipo_pago_nombre == null ? undefined : String(row.tipo_pago_nombre),

    tipo_pago_descripcion: row.tipo_pago_descripcion == null ? null : String(row.tipo_pago_descripcion),

    monto: Number(row.monto),

    estado_id: Number(row.estado_id),

    vigencia_desde: row.vigencia_desde ?? null,

    vigencia_hasta: row.vigencia_hasta ?? null,

    es_vigente: row.es_vigente == null ? null : Number(row.es_vigente),

    created_at: row.created_at ?? null,

    updated_at: row.updated_at ?? null,
  };
}

/* ============================================================
   SELECT BASE
============================================================ */

const SELECT_TARIFA = `
  SELECT
    ta.id,
    ta.academia_id,
    ta.tipo_pago_id,
    ta.monto,
    ta.estado_id,
    ta.vigencia_desde,
    ta.vigencia_hasta,
    ta.es_vigente,
    ta.created_at,
    ta.updated_at,

    tp.nombre
      AS tipo_pago_nombre,

    tp.descripcion
      AS tipo_pago_descripcion

  FROM tarifas_academia ta

  INNER JOIN tipo_pago tp
    ON tp.id =
       ta.tipo_pago_id
`;

/* ============================================================
   OBTENER TARIFA POR ID
============================================================ */

async function getTarifa(academiaId: number, id: number, executor: any = db) {
  const [rows]: any = await executor.query(
    `
        ${SELECT_TARIFA}

        WHERE ta.id = ?
          AND ta.academia_id = ?

        LIMIT 1
      `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

/* ============================================================
   OBTENER TARIFA PARA UPDATE / LOCK
============================================================ */

async function getTarifaForUpdate(academiaId: number, id: number, connection: any) {
  const [rows]: any = await connection.query(
    `
        SELECT
          id,
          academia_id,
          tipo_pago_id,
          monto,
          estado_id,
          vigencia_desde,
          vigencia_hasta,
          es_vigente,
          created_at,
          updated_at

        FROM tarifas_academia

        WHERE id = ?
          AND academia_id = ?

        LIMIT 1

        FOR UPDATE
      `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

/* ============================================================
   OBTENER TARIFA VIGENTE POR TIPO
============================================================ */

async function getTarifaVigente(academiaId: number, tipoPagoId: number, executor: any = db) {
  const [rows]: any = await executor.query(
    `
        ${SELECT_TARIFA}

        WHERE ta.academia_id = ?
          AND ta.tipo_pago_id = ?
          AND ta.es_vigente = 1

        LIMIT 1
      `,
    [academiaId, tipoPagoId]
  );

  return rows?.length ? rows[0] : null;
}

/* ============================================================
   TARIFA VIGENTE PARA UPDATE / LOCK
============================================================ */

async function getTarifaVigenteForUpdate(academiaId: number, tipoPagoId: number, connection: any) {
  const [rows]: any = await connection.query(
    `
        SELECT
          id,
          academia_id,
          tipo_pago_id,
          monto,
          estado_id,
          vigencia_desde,
          vigencia_hasta,
          es_vigente,
          created_at,
          updated_at

        FROM tarifas_academia

        WHERE academia_id = ?
          AND tipo_pago_id = ?
          AND es_vigente = 1

        LIMIT 1

        FOR UPDATE
      `,
    [academiaId, tipoPagoId]
  );

  return rows?.length ? rows[0] : null;
}

/* ============================================================
   VALIDAR TIPO DE PAGO HABILITADO
============================================================ */

async function validateTipoPagoEnabled(academiaId: number, tipoPagoId: number, executor: any = db) {
  const [rows]: any = await executor.query(
    `
        SELECT
          atp.id,

          atp.estado_id
            AS academia_estado_id,

          tp.estado_id
            AS global_estado_id

        FROM academia_tipo_pago atp

        INNER JOIN tipo_pago tp
          ON tp.id =
             atp.tipo_pago_id

        WHERE atp.academia_id = ?
          AND atp.tipo_pago_id = ?

        LIMIT 1
      `,
    [academiaId, tipoPagoId]
  );

  if (!Array.isArray(rows) || !rows.length) {
    throw makeHttpError(400, "El tipo de pago no está asociado a la academia");
  }

  if (Number(rows[0].global_estado_id) !== 1) {
    throw makeHttpError(409, "El tipo de pago se encuentra deshabilitado globalmente");
  }

  if (Number(rows[0].academia_estado_id) !== 1) {
    throw makeHttpError(400, "El tipo de pago no se encuentra habilitado para la academia");
  }
}

/* ============================================================
   DEPENDENCIAS HISTÓRICAS
============================================================ */

async function hasPaymentDependencies(tarifaId: number) {
  const [rows]: any = await db.query(
    `
        SELECT
          id

        FROM pago_detalle

        WHERE tarifa_id = ?

        LIMIT 1
      `,
    [tarifaId]
  );

  return Array.isArray(rows) && rows.length > 0;
}

/* ============================================================
   CERRAR TARIFA VIGENTE
============================================================ */

async function cerrarTarifa(connection: any, academiaId: number, tarifaId: number) {
  const [result]: any = await connection.query(
    `
        UPDATE tarifas_academia

        SET
          estado_id = 0,
          es_vigente = NULL,
          vigencia_hasta = NOW()

        WHERE id = ?
          AND academia_id = ?
          AND es_vigente = 1

        LIMIT 1
      `,
    [tarifaId, academiaId]
  );

  if (Number(result?.affectedRows ?? 0) === 0) {
    throw makeHttpError(409, "La tarifa ya no se encuentra vigente");
  }
}

/* ============================================================
   CREAR NUEVA VERSIÓN
============================================================ */

async function crearTarifaVigente(
  connection: any,
  academiaId: number,
  tipoPagoId: number,
  monto: number
): Promise<number> {
  const [result]: any = await connection.query(
    `
        INSERT INTO tarifas_academia (
          academia_id,
          tipo_pago_id,
          monto,
          vigencia_desde,
          vigencia_hasta,
          es_vigente,
          estado_id
        )

        VALUES (
          ?,
          ?,
          ?,
          NOW(),
          NULL,
          1,
          1
        )
      `,
    [academiaId, tipoPagoId, monto]
  );

  return Number(result?.insertId);
}

/* ============================================================
   ERRORES
============================================================ */

function handleDatabaseError(reply: FastifyReply, err: any, operation: string) {
  reply.header("Cache-Control", "no-store");

  const status = Number(err?.statusCode ?? 0);

  if ([400, 401, 403, 404, 409].includes(status)) {
    return reply.code(status).send({
      ok: false,

      message: err?.message ?? "No fue posible procesar la solicitud",
    });
  }

  if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
    return reply.code(409).send({
      ok: false,

      message: "Ya existe una tarifa vigente para este tipo de pago en la academia",
    });
  }

  if (
    err?.errno === 1451 ||
    err?.code === "ER_ROW_IS_REFERENCED_2" ||
    String(err?.code ?? "").includes("ER_ROW_IS_REFERENCED")
  ) {
    return reply.code(409).send({
      ok: false,

      message: "La tarifa posee información financiera relacionada y no puede eliminarse",
    });
  }

  if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
    return reply.code(409).send({
      ok: false,

      message: "La academia o el tipo de pago indicado no existe",
    });
  }

  console.error(`[tarifas_academia] ${operation}`, err);

  return reply.code(500).send({
    ok: false,

    message: `Error al ${operation}`,

    detail: err?.message,
  });
}

/* ============================================================
   ROUTER
============================================================ */

export default async function tarifas_academia(app: FastifyInstance) {
  /*
   * Admin y Superadmin pueden administrar
   * tarifas de la academia efectiva.
   */
  const canRead = [requireAuth, requireRoles([1, 3])];

  const canWrite = [requireAuth, requireRoles([1, 3])];

  /* ==========================================================
     HEALTH
  ========================================================== */

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
          module: "tarifas_academia",

          status: "ready",

          academia_id: academiaId,

          versionado: true,

          timestamp: new Date().toISOString(),
        });
      } catch (err: any) {
        return handleDatabaseError(reply, err, "consultar módulo de tarifas");
      }
    }
  );

  /* ==========================================================
     GET /

     Por defecto:
     - solo tarifas vigentes.

     ?incluir_historial=1
     - incluye todas las versiones.
  ========================================================== */

  app.get(
    "/",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const academiaId = resolveAcademiaId(req);

        const query = QuerySchema.parse(req.query);

        const where: string[] = ["ta.academia_id = ?"];

        const values: any[] = [academiaId];

        if (!query.incluir_historial) {
          where.push("ta.es_vigente = 1");
        }

        if (query.tipo_pago_id !== undefined) {
          where.push("ta.tipo_pago_id = ?");

          values.push(query.tipo_pago_id);
        }

        if (query.estado_id !== undefined) {
          where.push("ta.estado_id = ?");

          values.push(query.estado_id);
        }

        values.push(query.limit);

        const [rows]: any = await db.query(
          `
              ${SELECT_TARIFA}

              WHERE
                ${where.join(" AND ")}

              ORDER BY
                tp.nombre ASC,

                CASE
                  WHEN ta.es_vigente = 1
                  THEN 0
                  ELSE 1
                END ASC,

                ta.vigencia_desde DESC,
                ta.id DESC

              LIMIT ?
            `,
          values
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          academia_id: academiaId,

          incluye_historial: query.incluir_historial,

          count: rows?.length ?? 0,

          items: (rows ?? []).map(normalize),
        });
      } catch (err: any) {
        if (err instanceof ZodError) {
          reply.header("Cache-Control", "no-store");

          return reply.code(400).send({
            ok: false,

            message: "Parámetros inválidos",

            detail: zodDetail(err),
          });
        }

        return handleDatabaseError(reply, err, "listar tarifas de academia");
      }
    }
  );

  /* ==========================================================
     GET /tipo/:tipoPagoId

     Obtiene tarifa vigente de un tipo de pago.
  ========================================================== */

  app.get(
    "/tipo/:id",
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

        const row = await getTarifaVigente(academiaId, parsed.data.id);

        reply.header("Cache-Control", "no-store");

        if (!row) {
          return reply.code(404).send({
            ok: false,

            message: "No existe una tarifa vigente para este tipo de pago",
          });
        }

        return reply.send({
          ok: true,

          item: normalize(row),
        });
      } catch (err: any) {
        return handleDatabaseError(reply, err, "obtener tarifa vigente");
      }
    }
  );

  /* ==========================================================
     GET /:id

     Puede obtener:
     - tarifa vigente;
     - tarifa histórica.
  ========================================================== */

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
        return handleDatabaseError(reply, err, "obtener tarifa");
      }
    }
  );

  /* ==========================================================
     POST /

     CREA UNA NUEVA TARIFA VIGENTE.

     Si ya existe una tarifa vigente para:
     academia + tipo_pago
     devuelve 409.

     Si solo existen tarifas históricas:
     permite crear nueva vigencia.
  ========================================================== */

  app.post(
    "/",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      let connection: any = null;

      try {
        const academiaId = resolveAcademiaId(req);

        const body = CreateSchema.parse(req.body);

        /*
         * Una tarifa nueva siempre
         * debe comenzar vigente.
         */
        if (Number(body.estado_id) !== 1) {
          return reply.code(400).send({
            ok: false,

            message: "Una tarifa nueva debe crearse activa",
          });
        }

        connection = await db.getConnection();

        await connection.beginTransaction();

        /*
         * La validación se ejecuta dentro
         * de la misma transacción.
         */
        await validateTipoPagoEnabled(academiaId, body.tipo_pago_id, connection);

        /*
         * Bloqueamos una eventual tarifa
         * vigente concurrente.
         */
        const current = await getTarifaVigenteForUpdate(academiaId, body.tipo_pago_id, connection);

        if (current) {
          throw makeHttpError(409, "Ya existe una tarifa vigente para este tipo de pago en la academia");
        }

        const insertId = await crearTarifaVigente(connection, academiaId, body.tipo_pago_id, Number(body.monto));

        await connection.commit();

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

                tipo_pago_id: body.tipo_pago_id,

                monto: Number(body.monto),

                estado_id: 1,

                es_vigente: 1,
              },
        });
      } catch (err: any) {
        if (connection) {
          try {
            await connection.rollback();
          } catch {
            // No-op
          }
        }

        if (err instanceof ZodError) {
          reply.header("Cache-Control", "no-store");

          return reply.code(400).send({
            ok: false,

            message: "Payload inválido",

            detail: zodDetail(err),
          });
        }

        return handleDatabaseError(reply, err, "crear tarifa");
      } finally {
        if (connection) {
          connection.release();
        }
      }
    }
  );

  /* ==========================================================
     PUT /:id

     REEMPLAZO FUNCIONAL DE TARIFA VIGENTE.

     IMPORTANTE:
     NO actualiza monto histórico.

     Si cambia el monto:
     1. cierra tarifa actual;
     2. inserta nueva versión.

     estado_id = 0:
     cierra tarifa sin crear reemplazo.
  ========================================================== */

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

      let connection: any = null;

      try {
        const academiaId = resolveAcademiaId(req);

        const id = parsed.data.id;

        const body = PutSchema.parse(req.body);

        connection = await db.getConnection();

        await connection.beginTransaction();

        const current = await getTarifaForUpdate(academiaId, id, connection);

        if (!current) {
          throw makeHttpError(404, "Tarifa no encontrada");
        }

        /*
         * Una tarifa histórica
         * jamás se modifica.
         */
        if (Number(current.es_vigente) !== 1) {
          throw makeHttpError(409, "La tarifa es histórica y no puede modificarse");
        }

        /*
         * La identidad del concepto
         * NO puede cambiar.
         */
        if (Number(body.tipo_pago_id) !== Number(current.tipo_pago_id)) {
          throw makeHttpError(409, "No se puede cambiar el tipo de pago de una tarifa existente");
        }

        await validateTipoPagoEnabled(academiaId, current.tipo_pago_id, connection);

        /*
         * estado_id = 0:
         * cerrar tarifa sin reemplazo.
         */
        if (Number(body.estado_id) === 0) {
          await cerrarTarifa(connection, academiaId, id);

          await connection.commit();

          const closed = await getTarifa(academiaId, id);

          return reply.send({
            ok: true,

            action: "closed",

            item: closed ? normalize(closed) : null,
          });
        }

        const nuevoMonto = Number(body.monto);

        const montoActual = Number(current.monto);

        /*
         * Si no cambió nada,
         * no creamos una versión inútil.
         */
        if (nuevoMonto === montoActual) {
          await connection.commit();

          const same = await getTarifa(academiaId, id);

          return reply.send({
            ok: true,

            action: "unchanged",

            item: same ? normalize(same) : null,
          });
        }

        /*
         * VERSIONADO:
         *
         * cerrar anterior.
         */
        await cerrarTarifa(connection, academiaId, id);

        /*
         * crear nueva.
         */
        const newId = await crearTarifaVigente(connection, academiaId, current.tipo_pago_id, nuevoMonto);

        await connection.commit();

        const updated = await getTarifa(academiaId, newId);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          action: "versioned",

          previous_tarifa_id: id,

          tarifa_id: newId,

          item: updated ? normalize(updated) : null,
        });
      } catch (err: any) {
        if (connection) {
          try {
            await connection.rollback();
          } catch {
            // No-op
          }
        }

        if (err instanceof ZodError) {
          reply.header("Cache-Control", "no-store");

          return reply.code(400).send({
            ok: false,

            message: "Payload inválido",

            detail: zodDetail(err),
          });
        }

        return handleDatabaseError(reply, err, "actualizar tarifa");
      } finally {
        if (connection) {
          connection.release();
        }
      }
    }
  );

  /* ==========================================================
     PATCH /:id

     ACTUALIZACIÓN PARCIAL.

     Misma regla:
     - tarifa histórica = inmutable;
     - monto distinto = nueva versión;
     - estado_id 0 = cierre;
     - tipo_pago_id NO puede cambiar.
  ========================================================== */

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

      let connection: any = null;

      try {
        const academiaId = resolveAcademiaId(req);

        const id = parsed.data.id;

        const body = PatchSchema.parse(req.body);

        if (Object.keys(body).length === 0) {
          return reply.code(400).send({
            ok: false,

            message: "No hay campos para actualizar",
          });
        }

        connection = await db.getConnection();

        await connection.beginTransaction();

        const current = await getTarifaForUpdate(academiaId, id, connection);

        if (!current) {
          throw makeHttpError(404, "Tarifa no encontrada");
        }

        if (Number(current.es_vigente) !== 1) {
          throw makeHttpError(409, "La tarifa es histórica y no puede modificarse");
        }

        /*
         * Aunque venga tipo_pago_id,
         * debe corresponder al mismo concepto.
         */
        if (body.tipo_pago_id !== undefined && Number(body.tipo_pago_id) !== Number(current.tipo_pago_id)) {
          throw makeHttpError(409, "No se puede cambiar el tipo de pago de una tarifa existente");
        }

        await validateTipoPagoEnabled(academiaId, current.tipo_pago_id, connection);

        /*
         * Cierre explícito.
         */
        if (body.estado_id === 0) {
          await cerrarTarifa(connection, academiaId, id);

          await connection.commit();

          const closed = await getTarifa(academiaId, id);

          return reply.send({
            ok: true,

            action: "closed",

            item: closed ? normalize(closed) : null,
          });
        }

        const montoActual = Number(current.monto);

        const nuevoMonto = body.monto !== undefined ? Number(body.monto) : montoActual;

        /*
         * Si no cambió monto:
         * no generamos versión.
         */
        if (nuevoMonto === montoActual) {
          await connection.commit();

          const same = await getTarifa(academiaId, id);

          return reply.send({
            ok: true,

            action: "unchanged",

            item: same ? normalize(same) : null,
          });
        }

        /*
         * Cerrar versión anterior.
         */
        await cerrarTarifa(connection, academiaId, id);

        /*
         * Crear nueva versión.
         */
        const newId = await crearTarifaVigente(connection, academiaId, current.tipo_pago_id, nuevoMonto);

        await connection.commit();

        const updated = await getTarifa(academiaId, newId);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          action: "versioned",

          previous_tarifa_id: id,

          tarifa_id: newId,

          item: updated ? normalize(updated) : null,
        });
      } catch (err: any) {
        if (connection) {
          try {
            await connection.rollback();
          } catch {
            // No-op
          }
        }

        if (err instanceof ZodError) {
          reply.header("Cache-Control", "no-store");

          return reply.code(400).send({
            ok: false,

            message: "Payload inválido",

            detail: zodDetail(err),
          });
        }

        return handleDatabaseError(reply, err, "actualizar tarifa");
      } finally {
        if (connection) {
          connection.release();
        }
      }
    }
  );

  /* ==========================================================
     DELETE /:id

     Borrado físico permitido SOLO si:
     - pertenece a la academia;
     - no posee pago_detalle asociado.

     Para una tarifa utilizada:
     nunca se elimina.

     Para conservar historial normalmente se recomienda
     cerrar la tarifa mediante PATCH estado_id = 0.
  ========================================================== */

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

        const current = await getTarifa(academiaId, id);

        if (!current) {
          return reply.code(404).send({
            ok: false,

            message: "Tarifa no encontrada",
          });
        }

        if (await hasPaymentDependencies(id)) {
          return reply.code(409).send({
            ok: false,

            message: "La tarifa posee historial financiero y no puede eliminarse",
          });
        }

        const [result]: any = await db.query(
          `
              DELETE
              FROM tarifas_academia

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
        return handleDatabaseError(reply, err, "eliminar tarifa");
      }
    }
  );
}
