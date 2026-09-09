// src/routes/routers/tarifas_academia.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z, ZodError } from "zod";

import { db } from "../db";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * Tabla: tarifas_academia
 *
 * Campos:
 * - id
 * - academia_id
 * - tipo_pago_id
 * - monto
 * - estado_id
 * - created_at
 * - updated_at
 *
 * Seguridad:
 * - READ: roles 1, 3
 * - WRITE: roles 1, 3
 *
 * academia_id:
 * - Admin: academia firmada en JWT.
 * - Superadmin: x-academia-id validado.
 * - Nunca se recibe academia_id desde el body.
 *
 * Reglas:
 * - tipo_pago_id referencia tipo_pago global.
 * - el tipo de pago debe estar habilitado para la academia
 *   mediante academia_tipo_pago.
 * - solo puede existir una tarifa por academia + tipo_pago_id.
 * - la tarifa histórica no debe eliminarse si ya fue utilizada
 *   por pago_detalle.
 */

/* =========================================================
   SCHEMAS
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive(),

    monto: z.coerce.number().finite().nonnegative().max(999999999.99),

    estado_id: z.coerce.number().int().positive().max(255).default(1),
  })
  .strict();

const PutSchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive(),

    monto: z.coerce.number().finite().nonnegative().max(999999999.99),

    estado_id: z.coerce.number().int().positive().max(255),
  })
  .strict();

const PatchSchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive().optional(),

    monto: z.coerce.number().finite().nonnegative().max(999999999.99).optional(),

    estado_id: z.coerce.number().int().positive().max(255).optional(),
  })
  .strict();

const QuerySchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive().optional(),

    estado_id: z.coerce.number().int().positive().max(255).optional(),

    limit: z.coerce.number().int().min(1).max(500).default(200),
  })
  .strict();

/* =========================================================
   HELPERS
========================================================= */

function zodDetail(err: ZodError): string {
  return err.issues.map((issue) => `${issue.path.join(".") || "field"}: ${issue.message}`).join("; ");
}

function resolveAcademiaId(req: FastifyRequest): number {
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

    tipo_pago_id: Number(row.tipo_pago_id),

    tipo_pago_nombre: row.tipo_pago_nombre == null ? undefined : String(row.tipo_pago_nombre),

    tipo_pago_descripcion: row.tipo_pago_descripcion == null ? null : String(row.tipo_pago_descripcion),

    monto: Number(row.monto),

    estado_id: Number(row.estado_id),

    created_at: row.created_at ?? null,

    updated_at: row.updated_at ?? null,
  };
}

/* =========================================================
   OBTENER TARIFA
========================================================= */

async function getTarifa(academiaId: number, id: number) {
  const [rows]: any = await db.query(
    `
        SELECT
          ta.id,
          ta.academia_id,
          ta.tipo_pago_id,
          ta.monto,
          ta.estado_id,
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

        WHERE ta.id = ?
          AND ta.academia_id = ?

        LIMIT 1
      `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

/* =========================================================
   VALIDAR TIPO HABILITADO
========================================================= */

async function validateTipoPagoEnabled(academiaId: number, tipoPagoId: number) {
  const [rows]: any = await db.query(
    `
        SELECT
          atp.id,
          atp.estado_id

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

  if (!rows?.length) {
    throw new Error("El tipo de pago no está asociado a la academia");
  }

  if (Number(rows[0].estado_id) !== 1) {
    throw new Error("El tipo de pago no se encuentra habilitado para la academia");
  }
}

/* =========================================================
   DUPLICIDAD
========================================================= */

async function existsTarifa(academiaId: number, tipoPagoId: number, excludeId?: number) {
  const values: any[] = [academiaId, tipoPagoId];

  let sql = `
    SELECT id

    FROM tarifas_academia

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

  const [rows]: any = await db.query(sql, values);

  return Array.isArray(rows) && rows.length > 0;
}

/* =========================================================
   DEPENDENCIAS HISTÓRICAS
========================================================= */

async function hasPaymentDependencies(tarifaId: number) {
  const [rows]: any = await db.query(
    `
        SELECT id

        FROM pago_detalle

        WHERE tarifa_id = ?

        LIMIT 1
      `,
    [tarifaId]
  );

  return Array.isArray(rows) && rows.length > 0;
}

/* =========================================================
   ERRORES SCOPE
========================================================= */

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

/* =========================================================
   VALIDACIONES DE NEGOCIO
========================================================= */

function isBusinessValidationError(err: any) {
  const message = String(err?.message ?? "");

  return [
    "El tipo de pago no está asociado a la academia",
    "El tipo de pago no se encuentra habilitado para la academia",
  ].includes(message);
}

/* =========================================================
   ROUTER
========================================================= */

export default async function tarifas_academia(app: FastifyInstance) {
  /*
   * Seguridad:
   *
   * READ:
   * - Admin
   * - Superadmin
   *
   * WRITE:
   * - Admin
   * - Superadmin
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
          module: "tarifas_academia",

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

          message: "Error en módulo tarifas_academia",
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
      try {
        const academiaId = resolveAcademiaId(req);

        const query = QuerySchema.parse(req.query);

        const where: string[] = ["ta.academia_id = ?"];

        const values: any[] = [academiaId];

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
              SELECT
                ta.id,
                ta.academia_id,
                ta.tipo_pago_id,
                ta.monto,
                ta.estado_id,
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

              WHERE
                ${where.join(" AND ")}

              ORDER BY
                tp.nombre ASC,
                ta.id ASC

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

        const handled = handleScopeError(reply, err);

        if (handled) {
          return handled;
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al listar tarifas de academia",
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

        if (handled) {
          return handled;
        }

        reply.header("Cache-Control", "no-store");

        return reply.code(500).send({
          ok: false,

          message: "Error al obtener tarifa",
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
      try {
        const academiaId = resolveAcademiaId(req);

        const body = CreateSchema.parse(req.body);

        await validateTipoPagoEnabled(academiaId, body.tipo_pago_id);

        const duplicate = await existsTarifa(academiaId, body.tipo_pago_id);

        if (duplicate) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "Ya existe una tarifa para este tipo de pago en la academia",
          });
        }

        const [result]: any = await db.query(
          `
              INSERT INTO tarifas_academia (
                academia_id,
                tipo_pago_id,
                monto,
                estado_id
              )

              VALUES (?, ?, ?, ?)
            `,
          [academiaId, body.tipo_pago_id, body.monto, body.estado_id]
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

                tipo_pago_id: body.tipo_pago_id,

                monto: Number(body.monto),

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

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "Ya existe una tarifa para este tipo de pago en la academia",
          });
        }

        if (isBusinessValidationError(err)) {
          return reply.code(400).send({
            ok: false,
            message: err.message,
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

          message: "Error al crear tarifa",
        });
      }
    }
  );

  /* =======================================================
     PUT /:id
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

        const current = await getTarifa(academiaId, id);

        if (!current) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Tarifa no encontrada",
          });
        }

        const body = PutSchema.parse(req.body);

        const changingTipoPago = Number(body.tipo_pago_id) !== Number(current.tipo_pago_id);

        /*
         * Si la tarifa ya fue utilizada,
         * no se permite cambiar su identidad
         * hacia otro tipo_pago.
         *
         * El monto sí puede cambiar porque
         * pago_detalle conserva el snapshot histórico.
         */
        if (changingTipoPago && (await hasPaymentDependencies(id))) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "La tarifa posee historial financiero y no puede cambiar de tipo de pago",
          });
        }

        await validateTipoPagoEnabled(academiaId, body.tipo_pago_id);

        const duplicate = await existsTarifa(academiaId, body.tipo_pago_id, id);

        if (duplicate) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "Ya existe otra tarifa para este tipo de pago en la academia",
          });
        }

        const [result]: any = await db.query(
          `
              UPDATE tarifas_academia

              SET
                tipo_pago_id = ?,
                monto = ?,
                estado_id = ?

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [body.tipo_pago_id, body.monto, body.estado_id, id, academiaId]
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

          updated: updated
            ? normalize(updated)
            : {
                id,

                academia_id: academiaId,

                tipo_pago_id: body.tipo_pago_id,

                monto: Number(body.monto),

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

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "Ya existe otra tarifa para este tipo de pago en la academia",
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

          message: "Error al actualizar tarifa",
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

        const current = await getTarifa(academiaId, id);

        if (!current) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Tarifa no encontrada",
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

        const tipoPagoId = body.tipo_pago_id ?? Number(current.tipo_pago_id);

        const monto = body.monto ?? Number(current.monto);

        const estadoId = body.estado_id ?? Number(current.estado_id);

        const changingTipoPago = Number(tipoPagoId) !== Number(current.tipo_pago_id);

        if (changingTipoPago && (await hasPaymentDependencies(id))) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "La tarifa posee historial financiero y no puede cambiar de tipo de pago",
          });
        }

        if (body.tipo_pago_id !== undefined) {
          await validateTipoPagoEnabled(academiaId, tipoPagoId);

          const duplicate = await existsTarifa(academiaId, tipoPagoId, id);

          if (duplicate) {
            reply.header("Cache-Control", "no-store");

            return reply.code(409).send({
              ok: false,

              message: "Ya existe otra tarifa para este tipo de pago en la academia",
            });
          }
        }

        const [result]: any = await db.query(
          `
              UPDATE tarifas_academia

              SET
                tipo_pago_id = ?,
                monto = ?,
                estado_id = ?

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [tipoPagoId, monto, estadoId, id, academiaId]
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

          updated: updated
            ? normalize(updated)
            : {
                id,

                academia_id: academiaId,

                tipo_pago_id: tipoPagoId,

                monto,

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

        const handled = handleScopeError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "Ya existe otra tarifa para este tipo de pago en la academia",
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

          message: "Error al actualizar tarifa",
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

        const current = await getTarifa(academiaId, id);

        if (!current) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Tarifa no encontrada",
          });
        }

        if (await hasPaymentDependencies(id)) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "La tarifa posee historial financiero y no puede eliminarse. Debe desactivarse mediante estado_id",
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
        reply.header("Cache-Control", "no-store");

        const handled = handleScopeError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1451 || String(err?.code ?? "").includes("ER_ROW_IS_REFERENCED")) {
          return reply.code(409).send({
            ok: false,

            message: "No se puede eliminar la tarifa porque está siendo utilizada",

            detail: err?.sqlMessage ?? err?.message,
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al eliminar tarifa",
        });
      }
    }
  );
}
