// src/routers/planes.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z, ZodError } from "zod";

import { db } from "../db";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

const LEGACY_PERIODICIDAD = "MENSUAL";

/**
 * Tabla: planes_academia
 *
 * Campos:
 * - id
 * - academia_id
 * - nombre
 * - descripcion
 * - periodicidad (legacy interno; no forma parte del contrato API)
 * - estado_id
 * - created_at
 * - updated_at
 *
 * Scope:
 * - Multi-academia
 *
 * Seguridad:
 * - READ: roles 1, 3
 * - WRITE: roles 1, 3
 *
 * academia_id:
 * - Admin: JWT firmado
 * - Superadmin: x-academia-id validado
 *
 * Nunca se confía en academia_id proveniente del body.
 */

/* =========================================================
   Schemas
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(120),

    descripcion: z.string().trim().max(500).nullable().optional(),

    estado_id: z.coerce.number().int().positive().max(255).default(1),
  })
  .strict();

const PutSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(120),

    descripcion: z.string().trim().max(500).nullable(),

    estado_id: z.coerce.number().int().positive().max(255),
  })
  .strict();

const PatchSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(120).optional(),

    descripcion: z.string().trim().max(500).nullable().optional(),

    estado_id: z.coerce.number().int().positive().max(255).optional(),
  })
  .strict();

/* =========================================================
   Helpers
========================================================= */

function zodDetail(err: ZodError) {
  return err.issues.map((issue) => `${issue.path.join(".") || "field"}: ${issue.message}`).join("; ");
}

function normalize(row: any) {
  return {
    id: Number(row.id),

    academia_id: Number(row.academia_id),

    nombre: String(row.nombre ?? ""),

    descripcion: row.descripcion == null ? null : String(row.descripcion),

    estado_id: Number(row.estado_id),

    created_at: row.created_at ?? null,

    updated_at: row.updated_at ?? null,
  };
}

/**
 * Obtiene academia efectiva utilizando exclusivamente
 * el contexto autenticado.
 *
 * Admin:
 * JWT.
 *
 * Superadmin:
 * x-academia-id.
 */
function resolveAcademiaId(req: FastifyRequest) {
  const academiaId = Number(getEffectiveAcademiaId(req));

  if (!Number.isInteger(academiaId) || academiaId <= 0) {
    const error: any = new Error("Academia efectiva inválida");

    error.statusCode = 403;

    throw error;
  }

  return academiaId;
}


function normalizeDescripcion(value: string | null | undefined) {
  if (value === null || value === undefined) {
    return null;
  }

  const text = String(value).trim();

  return text || null;
}

async function existsByNombre(academiaId: number, nombre: string, excludeId?: number) {
  const normalizedNombre = String(nombre ?? "").trim();

  if (!normalizedNombre) {
    return false;
  }

  if (excludeId) {
    const [rows]: any = await db.query(
      `
        SELECT id
        FROM planes_academia
        WHERE academia_id = ?
          AND LOWER(TRIM(nombre)) = LOWER(?)
          AND id <> ?
        LIMIT 1
        `,
      [academiaId, normalizedNombre, excludeId]
    );

    return Array.isArray(rows) && rows.length > 0;
  }

  const [rows]: any = await db.query(
    `
      SELECT id
      FROM planes_academia
      WHERE academia_id = ?
        AND LOWER(TRIM(nombre)) = LOWER(?)
      LIMIT 1
      `,
    [academiaId, normalizedNombre]
  );

  return Array.isArray(rows) && rows.length > 0;
}

async function existsById(academiaId: number, id: number) {
  const [rows]: any = await db.query(
    `
      SELECT id
      FROM planes_academia
      WHERE id = ?
        AND academia_id = ?
      LIMIT 1
      `,
    [id, academiaId]
  );

  return Array.isArray(rows) && rows.length > 0;
}

/* =========================================================
   Manejo común de errores
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
   Router
========================================================= */

export default async function planes(app: FastifyInstance) {
  /*
   * Lectura:
   * Admin, Superadmin.
   */
  const canRead = [requireAuth, requireRoles([1, 3])];

  /*
   * Escritura:
   * Admin, Superadmin.
   */
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
          module: "planes_academia",

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
              id,
              academia_id,
              nombre,
              descripcion,
              estado_id,
              created_at,
              updated_at
            FROM planes_academia
            WHERE academia_id = ?
            ORDER BY
              estado_id ASC,
              nombre ASC,
              id ASC
            `,
          [academiaId]
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          count: rows?.length ?? 0,

          items: (rows ?? []).map(normalize),
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

        const [rows]: any = await db.query(
          `
            SELECT
              id,
              academia_id,
              nombre,
              descripcion,
              estado_id,
              created_at,
              updated_at
            FROM planes_academia
            WHERE id = ?
              AND academia_id = ?
            LIMIT 1
            `,
          [id, academiaId]
        );

        reply.header("Cache-Control", "no-store");

        if (!rows?.length) {
          return reply.code(404).send({
            ok: false,
            message: "Plan no encontrado",
          });
        }

        return reply.send({
          ok: true,

          item: normalize(rows[0]),
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
         * CreateSchema es strict().
         *
         * Si frontend intenta mandar:
         *
         * academia_id
         *
         * el payload será rechazado.
         */
        const body = CreateSchema.parse(req.body);

        const nombre = body.nombre.trim();

        const descripcion = normalizeDescripcion(body.descripcion);

        const estadoId = Number(body.estado_id);

        const duplicate = await existsByNombre(academiaId, nombre);

        if (duplicate) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "Ya existe un plan con ese nombre en esta academia",
          });
        }

        const [result]: any = await db.query(
          `
            INSERT INTO planes_academia
            (
              academia_id,
              nombre,
              descripcion,
              estado_id
            )
            VALUES (?, ?, ?, ?, ?)
            `,
          [academiaId, nombre, descripcion, LEGACY_PERIODICIDAD, estadoId]
        );

        const insertId = Number(result?.insertId);

        /*
         * Recuperamos el registro realmente
         * almacenado para responder con
         * timestamps y valores definitivos.
         */
        const [rows]: any = await db.query(
          `
            SELECT
              id,
              academia_id,
              nombre,
              descripcion,
              estado_id,
              created_at,
              updated_at
            FROM planes_academia
            WHERE id = ?
              AND academia_id = ?
            LIMIT 1
            `,
          [insertId, academiaId]
        );

        reply.header("Cache-Control", "no-store");

        return reply.code(201).send({
          ok: true,

          id: insertId,

          item: rows?.length
            ? normalize(rows[0])
            : {
                id: insertId,

                academia_id: academiaId,

                nombre,

                descripcion,

  
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

            message: "Ya existe un plan con ese nombre en esta academia",
          });
        }

        if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
          return reply.code(409).send({
            ok: false,

            message: "La academia o alguno de los datos relacionados no existe",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al crear plan",

          detail: err?.message,
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

        const exists = await existsById(academiaId, id);

        if (!exists) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Plan no encontrado",
          });
        }

        const body = PutSchema.parse(req.body);

        const nombre = body.nombre.trim();

        const descripcion = normalizeDescripcion(body.descripcion);

        const estadoId = Number(body.estado_id);

        const duplicate = await existsByNombre(academiaId, nombre, id);

        if (duplicate) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "Ya existe otro plan con ese nombre en esta academia",
          });
        }

        const [result]: any = await db.query(
          `
            UPDATE planes_academia
            SET
              nombre = ?,
              descripcion = ?,
              estado_id = ?
            WHERE id = ?
              AND academia_id = ?
            LIMIT 1
            `,
          [nombre, descripcion, estadoId, id, academiaId]
        );

        reply.header("Cache-Control", "no-store");

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,

            message: "Plan no encontrado",
          });
        }

        const [rows]: any = await db.query(
          `
            SELECT
              id,
              academia_id,
              nombre,
              descripcion,
              estado_id,
              created_at,
              updated_at
            FROM planes_academia
            WHERE id = ?
              AND academia_id = ?
            LIMIT 1
            `,
          [id, academiaId]
        );

        return reply.send({
          ok: true,

          updated: rows?.length
            ? normalize(rows[0])
            : {
                id,
                academia_id: academiaId,
                nombre,
                descripcion,
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

            message: "Ya existe otro plan con ese nombre en esta academia",
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

        const exists = await existsById(academiaId, id);

        if (!exists) {
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

        if (body.nombre !== undefined) {
          const duplicate = await existsByNombre(academiaId, body.nombre, id);

          if (duplicate) {
            reply.header("Cache-Control", "no-store");

            return reply.code(409).send({
              ok: false,

              message: "Ya existe otro plan con ese nombre en esta academia",
            });
          }
        }

        /*
         * Construcción dinámica segura.
         *
         * Los nombres de columnas NO vienen del usuario.
         * Sólo añadimos columnas explícitamente permitidas.
         *
         * Los valores siguen siendo parametrizados.
         */
        const fields: string[] = [];

        const values: any[] = [];

        if (body.nombre !== undefined) {
          fields.push("nombre = ?");

          values.push(body.nombre.trim());
        }

        if (body.descripcion !== undefined) {
          fields.push("descripcion = ?");

          values.push(normalizeDescripcion(body.descripcion));
        }

        if (body.estado_id !== undefined) {
          fields.push("estado_id = ?");

          values.push(Number(body.estado_id));
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
            UPDATE planes_academia
            SET ${fields.join(", ")}
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

        const [rows]: any = await db.query(
          `
            SELECT
              id,
              academia_id,
              nombre,
              descripcion,
              estado_id,
              created_at,
              updated_at
            FROM planes_academia
            WHERE id = ?
              AND academia_id = ?
            LIMIT 1
            `,
          [id, academiaId]
        );

        return reply.send({
          ok: true,

          updated: rows?.length
            ? normalize(rows[0])
            : {
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

            message: "Ya existe otro plan con ese nombre en esta academia",
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

        const [result]: any = await db.query(
          `
            DELETE
            FROM planes_academia
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

        /*
         * Un plan utilizado por tarifas,
         * jugadores, promociones, etc.
         * no debe eliminarse físicamente.
         */
        if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
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
