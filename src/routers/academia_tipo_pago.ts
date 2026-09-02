// src/routers/academia_tipo_pago.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * Tabla: academia_tipo_pago
 *
 * Campos:
 * - id
 * - academia_id
 * - tipo_pago_id
 * - estado_id
 *
 * Scope:
 * - Multi-academia.
 *
 * Seguridad:
 * - READ: roles 1, 3
 * - WRITE: roles 1, 3
 * - Staff (rol 2): sin acceso.
 *
 * academia_id:
 * - Admin: academia firmada en JWT.
 * - Superadmin: x-academia-id validado por authz.
 * - Nunca se recibe academia_id desde el body.
 *
 * Reglas:
 * - tipo_pago_id referencia el catálogo GLOBAL tipo_pago.
 * - La misma academia no puede asociar dos veces el mismo tipo_pago_id.
 * - estado_id = 1 representa asociación habilitada según la política actual.
 * - Deshabilitar una asociación no elimina el tipo_pago global.
 * - No se permite eliminar una asociación utilizada por configuración comercial
 *   o registros operacionales dependientes.
 */

/* =========================================================
   Schemas
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive(),
    estado_id: z.coerce.number().int().positive().max(255).default(1),
  })
  .strict();

const PutSchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive(),
    estado_id: z.coerce.number().int().positive().max(255),
  })
  .strict();

const PatchSchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive().optional(),
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
   Helpers
========================================================= */

function zodDetail(err: ZodError) {
  return err.issues.map((issue) => `${issue.path.join(".") || "field"}: ${issue.message}`).join("; ");
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
    tipo_pago_id: Number(row.tipo_pago_id),
    estado_id: Number(row.estado_id),

    tipo_pago_nombre: row.tipo_pago_nombre == null ? undefined : String(row.tipo_pago_nombre),

    tipo_pago_descripcion: row.tipo_pago_descripcion == null ? null : String(row.tipo_pago_descripcion),
  };
}

async function getRelacion(academiaId: number, id: number) {
  const [rows]: any = await db.query(
    `
      SELECT
        atp.id,
        atp.academia_id,
        atp.tipo_pago_id,
        atp.estado_id,

        tp.nombre AS tipo_pago_nombre,
        tp.descripcion AS tipo_pago_descripcion

      FROM academia_tipo_pago atp

      INNER JOIN tipo_pago tp
        ON tp.id = atp.tipo_pago_id

      WHERE atp.id = ?
        AND atp.academia_id = ?

      LIMIT 1
    `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

async function validateTipoPagoGlobal(tipoPagoId: number) {
  const [rows]: any = await db.query(
    `
      SELECT id
      FROM tipo_pago
      WHERE id = ?
      LIMIT 1
    `,
    [tipoPagoId]
  );

  if (!rows?.length) {
    throw new Error("El tipo de pago no existe en el catálogo global");
  }
}

async function existsRelation(academiaId: number, tipoPagoId: number, excludeId?: number) {
  const values: any[] = [academiaId, tipoPagoId];

  let sql = `
    SELECT id
    FROM academia_tipo_pago
    WHERE academia_id = ?
      AND tipo_pago_id = ?
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
 * Protege relaciones que ya están utilizadas.
 *
 * Se revisan únicamente tablas que forman parte de la arquitectura
 * comercial acordada para WELI.
 */
async function relationHasDependencies(academiaId: number, tipoPagoId: number) {
  const [tarifas]: any = await db.query(
    `
      SELECT id
      FROM plan_tarifas
      WHERE academia_id = ?
        AND tipo_pago_id = ?
      LIMIT 1
    `,
    [academiaId, tipoPagoId]
  );

  if (tarifas?.length) {
    return {
      used: true,
      source: "plan_tarifas",
    };
  }

  const [promociones]: any = await db.query(
    `
      SELECT id
      FROM promocion_tipo_pago
      WHERE academia_id = ?
        AND tipo_pago_id = ?
      LIMIT 1
    `,
    [academiaId, tipoPagoId]
  );

  if (promociones?.length) {
    return {
      used: true,
      source: "promocion_tipo_pago",
    };
  }

  /*
   * pagos_jugador no posee academia_id.
   * El scope se obtiene mediante jugadores.
   */
  const [pagos]: any = await db.query(
    `
      SELECT p.id
      FROM pagos_jugador p

      INNER JOIN jugadores j
        ON j.rut_jugador = p.jugador_rut

      WHERE j.academia_id = ?
        AND p.tipo_pago_id = ?

      LIMIT 1
    `,
    [academiaId, tipoPagoId]
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
  return ["El tipo de pago no existe en el catálogo global"].includes(String(err?.message ?? ""));
}

/* =========================================================
   Router
========================================================= */

export default async function academia_tipo_pago(app: FastifyInstance) {
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
        const handled = handleScopeError(reply, err);

        if (handled) {
          return handled;
        }

        reply.header("Cache-Control", "no-store");

        return reply.code(500).send({
          ok: false,
          message: "Error en módulo academia_tipo_pago",
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

              tp.nombre AS tipo_pago_nombre,
              tp.descripcion AS tipo_pago_descripcion

            FROM academia_tipo_pago atp

            INNER JOIN tipo_pago tp
              ON tp.id = atp.tipo_pago_id

            WHERE ${where.join(" AND ")}

            ORDER BY
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

        const handled = handleScopeError(reply, err);

        if (handled) {
          return handled;
        }

        return reply.code(500).send({
          ok: false,
          message: "Error al listar tipos de pago de la academia",
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
          message: "Error al obtener tipo de pago de la academia",
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

        await validateTipoPagoGlobal(body.tipo_pago_id);

        const duplicate = await existsRelation(academiaId, body.tipo_pago_id);

        if (duplicate) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,
            message: "Este tipo de pago ya se encuentra asociado a la academia",
          });
        }

        const [result]: any = await db.query(
          `
            INSERT INTO academia_tipo_pago
            (
              academia_id,
              tipo_pago_id,
              estado_id
            )
            VALUES (?, ?, ?)
          `,
          [academiaId, body.tipo_pago_id, body.estado_id]
        );

        const insertId = Number(result?.insertId);

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
            message: "Este tipo de pago ya se encuentra asociado a la academia",
          });
        }

        if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
          return reply.code(409).send({
            ok: false,
            message: "La academia o el tipo de pago indicado no existe",
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
          message: "Error al asociar tipo de pago con academia",
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

        const current = await getRelacion(academiaId, id);

        if (!current) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,
            message: "Relación academia-tipo de pago no encontrada",
          });
        }

        const body = PutSchema.parse(req.body);

        const changingTipoPago = body.tipo_pago_id !== Number(current.tipo_pago_id);

        if (changingTipoPago) {
          const dependencies = await relationHasDependencies(academiaId, Number(current.tipo_pago_id));

          if (dependencies.used) {
            reply.header("Cache-Control", "no-store");

            return reply.code(409).send({
              ok: false,
              message: "La asociación actual está siendo utilizada y no puede cambiar de tipo de pago",
            });
          }
        }

        await validateTipoPagoGlobal(body.tipo_pago_id);

        const duplicate = await existsRelation(academiaId, body.tipo_pago_id, id);

        if (duplicate) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,
            message: "Ya existe otra asociación de esta academia con ese tipo de pago",
          });
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

        reply.header("Cache-Control", "no-store");

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,
            message: "Relación academia-tipo de pago no encontrada",
          });
        }

        const updated = await getRelacion(academiaId, id);

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

        const handled = handleScopeError(reply, err);

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

        if (isBusinessValidationError(err)) {
          return reply.code(400).send({
            ok: false,
            message: err.message,
          });
        }

        return reply.code(500).send({
          ok: false,
          message: "Error al actualizar tipo de pago de academia",
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
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,
            message: "Relación academia-tipo de pago no encontrada",
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
          tipo_pago_id: body.tipo_pago_id ?? Number(current.tipo_pago_id),

          estado_id: body.estado_id ?? Number(current.estado_id),
        };

        const changingTipoPago = merged.tipo_pago_id !== Number(current.tipo_pago_id);

        if (changingTipoPago) {
          const dependencies = await relationHasDependencies(academiaId, Number(current.tipo_pago_id));

          if (dependencies.used) {
            reply.header("Cache-Control", "no-store");

            return reply.code(409).send({
              ok: false,
              message: "La asociación actual está siendo utilizada y no puede cambiar de tipo de pago",
            });
          }
        }

        await validateTipoPagoGlobal(merged.tipo_pago_id);

        const duplicate = await existsRelation(academiaId, merged.tipo_pago_id, id);

        if (duplicate) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,
            message: "Ya existe otra asociación de esta academia con ese tipo de pago",
          });
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
          [merged.tipo_pago_id, merged.estado_id, id, academiaId]
        );

        reply.header("Cache-Control", "no-store");

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,
            message: "Relación academia-tipo de pago no encontrada",
          });
        }

        const updated = await getRelacion(academiaId, id);

        return reply.send({
          ok: true,

          updated: updated
            ? normalize(updated)
            : {
                id,
                academia_id: academiaId,
                tipo_pago_id: merged.tipo_pago_id,
                estado_id: merged.estado_id,
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
            message: "Ya existe otra asociación de esta academia con ese tipo de pago",
          });
        }

        if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
          return reply.code(409).send({
            ok: false,
            message: "La academia o el tipo de pago indicado no existe",
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
          message: "Error al actualizar tipo de pago de academia",
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
            message: "Relación academia-tipo de pago no encontrada",
          });
        }

        const dependencies = await relationHasDependencies(academiaId, Number(current.tipo_pago_id));

        if (dependencies.used) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,
            message:
              "El tipo de pago está siendo utilizado por la academia y no puede eliminarse. Debe desactivarse mediante estado_id",
          });
        }

        const [result]: any = await db.query(
          `
            DELETE FROM academia_tipo_pago
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
            message: "Relación academia-tipo de pago no encontrada",
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
            message: "No se puede eliminar la asociación porque está en uso",
            detail: err?.sqlMessage ?? err?.message,
          });
        }

        return reply.code(500).send({
          ok: false,
          message: "Error al eliminar tipo de pago de academia",
        });
      }
    }
  );
}
