// src/routers/prevision_medica.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z, ZodError } from "zod";
import { db } from "../db";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * ============================================================
 * PREVISIÓN MÉDICA
 * ============================================================
 *
 * Catálogo maestro:
 *   prevision_medica
 *
 * Campos:
 *   - id
 *   - nombre
 *   - estado_id          -> estado GLOBAL
 *   - created_at
 *   - updated_at
 *
 * Disponibilidad por academia:
 *
 *   academia_prevision_medica
 *
 * Campos:
 *   - academia_id
 *   - prevision_medica_id
 *   - estado_id          -> estado PARA ESA ACADEMIA
 *
 * Gobernanza:
 *
 * READ:
 *   - Admin       rol 1
 *   - Staff       rol 2
 *   - Superadmin  rol 3
 *
 * WRITE estructural:
 *   - exclusivamente Superadmin
 *
 * DISPONIBILIDAD POR ACADEMIA:
 *   - Admin
 *   - Superadmin
 *
 * El academia_id nunca se recibe desde el body.
 * Siempre se determina mediante getEffectiveAcademiaId(req).
 * ============================================================
 */

/* ============================================================
   SCHEMAS
============================================================ */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const ListQuerySchema = z
  .object({
    search: z.string().trim().max(120).optional().default(""),

    estado_id: z.coerce.number().int().min(0).max(1).optional(),

    disponibilidad: z.coerce.number().int().min(0).max(1).optional(),
  })
  .strict();

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres").max(120, "Máximo 120 caracteres"),

    estado_id: z.coerce.number().int().min(0).max(1).default(1),
  })
  .strict();

const PutSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres").max(120, "Máximo 120 caracteres"),

    estado_id: z.coerce.number().int().min(0).max(1),
  })
  .strict();

const PatchSchema = z
  .object({
    nombre: z
      .string()
      .trim()
      .min(3, "El nombre debe tener al menos 3 caracteres")
      .max(120, "Máximo 120 caracteres")
      .optional(),

    estado_id: z.coerce.number().int().min(0).max(1).optional(),
  })
  .strict();

const DisponibilidadSchema = z
  .object({
    estado_id: z.coerce.number().int().min(0).max(1),
  })
  .strict();

/* ============================================================
   HELPERS
============================================================ */

function zodDetail(err: ZodError) {
  return err.issues.map((i) => `${i.path.join(".") || "field"}: ${i.message}`).join("; ");
}

function normalize(row: any) {
  const estadoGlobal = Number(row.estado_id ?? 0);

  const estadoAcademia = Number(row.estado_academia_id ?? 1);

  const disponible = estadoGlobal === 1 && estadoAcademia === 1;

  return {
    id: Number(row.id),

    nombre: String(row.nombre ?? ""),

    estado_id: estadoGlobal,

    estado_global_id: estadoGlobal,

    estado_academia_id: estadoAcademia,

    disponible,

    created_at: row.created_at ?? null,

    updated_at: row.updated_at ?? null,
  };
}

async function existsByNombre(nombre: string, excludeId?: number) {
  const n = String(nombre ?? "").trim();

  if (!n) {
    return false;
  }

  if (excludeId) {
    const [rows]: any = await db.query(
      `
          SELECT id
          FROM prevision_medica
          WHERE LOWER(TRIM(nombre)) = LOWER(TRIM(?))
            AND id <> ?
          LIMIT 1
        `,
      [n, excludeId]
    );

    return Array.isArray(rows) && rows.length > 0;
  }

  const [rows]: any = await db.query(
    `
        SELECT id
        FROM prevision_medica
        WHERE LOWER(TRIM(nombre)) = LOWER(TRIM(?))
        LIMIT 1
      `,
    [n]
  );

  return Array.isArray(rows) && rows.length > 0;
}

async function previsionExists(id: number) {
  const [rows]: any = await db.query(
    `
        SELECT id
        FROM prevision_medica
        WHERE id = ?
        LIMIT 1
      `,
    [id]
  );

  return Array.isArray(rows) && rows.length > 0;
}

async function getPrevisionById(id: number, academiaId: number) {
  const [rows]: any = await db.query(
    `
        SELECT
          pm.id,
          pm.nombre,
          pm.estado_id,
          pm.created_at,
          pm.updated_at,

          COALESCE(
            apm.estado_id,
            1
          ) AS estado_academia_id

        FROM prevision_medica pm

        LEFT JOIN academia_prevision_medica apm
          ON apm.prevision_medica_id = pm.id
         AND apm.academia_id = ?

        WHERE pm.id = ?

        LIMIT 1
      `,
    [academiaId, id]
  );

  if (!Array.isArray(rows) || !rows.length) {
    return null;
  }

  return normalize(rows[0]);
}

/* ============================================================
   ROUTER
============================================================ */

export default async function prevision_medica(app: FastifyInstance) {
  /* ==========================================================
     PERMISOS
  ========================================================== */

  const canRead = [requireAuth, requireRoles([1, 2, 3])];

  const onlySuperadmin = [requireAuth, requireRoles([3])];

  const canManageAcademia = [requireAuth, requireRoles([1, 3])];

  /* ==========================================================
     HEALTH
  ========================================================== */

  app.get(
    "/health",
    {
      preHandler: canRead,
    },
    async (_req, reply) => {
      reply.header("Cache-Control", "no-store");

      return {
        module: "prevision_medica",

        status: "ready",

        timestamp: new Date().toISOString(),
      };
    }
  );

  /* ==========================================================
     GET /
  ========================================================== */

  app.get(
    "/",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = ListQuerySchema.safeParse(req.query);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "Parámetros de consulta inválidos",
          detail: zodDetail(parsed.error),
        });
      }

      try {
        const academiaId = Number(getEffectiveAcademiaId(req));

        if (!Number.isInteger(academiaId) || academiaId <= 0) {
          return reply.code(403).send({
            ok: false,
            message: "No se pudo determinar la academia",
          });
        }

        const { search, estado_id, disponibilidad } = parsed.data;

        const conditions: string[] = [];
        const params: any[] = [];

        if (search) {
          conditions.push(
            `
              LOWER(pm.nombre)
              LIKE LOWER(?)
            `
          );

          params.push(`%${search}%`);
        }

        if (estado_id !== undefined) {
          conditions.push("pm.estado_id = ?");

          params.push(estado_id);
        }

        if (disponibilidad !== undefined) {
          conditions.push(
            `
              CASE
                WHEN pm.estado_id = 1
                 AND COALESCE(
                       apm.estado_id,
                       1
                     ) = 1
                THEN 1
                ELSE 0
              END = ?
            `
          );

          params.push(disponibilidad);
        }

        const whereSql = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

        const [rows]: any = await db.query(
          `
              SELECT
                pm.id,
                pm.nombre,
                pm.estado_id,
                pm.created_at,
                pm.updated_at,

                COALESCE(
                  apm.estado_id,
                  1
                ) AS estado_academia_id

              FROM prevision_medica pm

              LEFT JOIN academia_prevision_medica apm
                ON apm.prevision_medica_id = pm.id
               AND apm.academia_id = ?

              ${whereSql}

              ORDER BY
                pm.nombre ASC,
                pm.id ASC
            `,
          [academiaId, ...params]
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          count: rows?.length ?? 0,

          items: (rows ?? []).map(normalize),
        });
      } catch (err: any) {
        req.log.error(
          {
            err,
          },
          "prevision_medica: error listando previsiones"
        );

        return reply.code(err?.statusCode === 403 ? 403 : 500).send({
          ok: false,

          message:
            err?.statusCode === 403 ? err?.message || "Academia no válida" : "Error al listar previsiones médicas",

          ...(err?.statusCode !== 403
            ? {
                detail: err?.message,
              }
            : {}),
        });
      }
    }
  );

  /* ==========================================================
     GET /:id
  ========================================================== */

  app.get(
    "/:id",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse(req.params);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      const id = parsed.data.id;

      try {
        const academiaId = Number(getEffectiveAcademiaId(req));

        if (!Number.isInteger(academiaId) || academiaId <= 0) {
          return reply.code(403).send({
            ok: false,
            message: "No se pudo determinar la academia",
          });
        }

        const item = await getPrevisionById(id, academiaId);

        reply.header("Cache-Control", "no-store");

        if (!item) {
          return reply.code(404).send({
            ok: false,
            message: "Previsión médica no encontrada",
          });
        }

        return reply.send({
          ok: true,
          item,
        });
      } catch (err: any) {
        req.log.error(
          {
            err,
            id,
          },
          "prevision_medica: error obteniendo previsión"
        );

        return reply.code(err?.statusCode === 403 ? 403 : 500).send({
          ok: false,

          message: err?.statusCode === 403 ? err?.message || "Academia no válida" : "Error al obtener previsión médica",

          ...(err?.statusCode !== 403
            ? {
                detail: err?.message,
              }
            : {}),
        });
      }
    }
  );

  /* ==========================================================
     POST /
     Crear previsión global
     SOLO SUPERADMIN
  ========================================================== */

  app.post(
    "/",
    {
      preHandler: onlySuperadmin,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const body = CreateSchema.parse(req.body);

        const nombre = body.nombre.trim();

        const estadoId = body.estado_id;

        const dup = await existsByNombre(nombre);

        if (dup) {
          return reply.code(409).send({
            ok: false,
            message: "Ya existe una previsión con ese nombre",
          });
        }

        const [result]: any = await db.query(
          `
              INSERT INTO prevision_medica (
                nombre,
                estado_id
              )
              VALUES (?, ?)
            `,
          [nombre, estadoId]
        );

        reply.header("Cache-Control", "no-store");

        return reply.code(201).send({
          ok: true,

          id: Number(result.insertId),

          item: {
            id: Number(result.insertId),

            nombre,

            estado_id: estadoId,
          },
        });
      } catch (err: any) {
        if (err instanceof ZodError) {
          return reply.code(400).send({
            ok: false,
            message: "Payload inválido",
            detail: zodDetail(err),
          });
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,
            message: "Ya existe una previsión con ese nombre",
          });
        }

        req.log.error(
          {
            err,
          },
          "prevision_medica: error creando previsión"
        );

        return reply.code(500).send({
          ok: false,
          message: "Error al crear previsión médica",
          detail: err?.message,
        });
      }
    }
  );

  /* ==========================================================
     PUT /:id
     Reemplazo estructural completo
     SOLO SUPERADMIN
  ========================================================== */

  app.put(
    "/:id",
    {
      preHandler: onlySuperadmin,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse(req.params);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      const id = parsed.data.id;

      try {
        const body = PutSchema.parse(req.body);

        const exists = await previsionExists(id);

        if (!exists) {
          return reply.code(404).send({
            ok: false,
            message: "Previsión médica no encontrada",
          });
        }

        const nombre = body.nombre.trim();

        const estadoId = body.estado_id;

        const dup = await existsByNombre(nombre, id);

        if (dup) {
          return reply.code(409).send({
            ok: false,
            message: "Nombre duplicado",
          });
        }

        await db.query(
          `
            UPDATE prevision_medica
            SET
              nombre = ?,
              estado_id = ?
            WHERE id = ?
          `,
          [nombre, estadoId, id]
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          updated: {
            id,
            nombre,
            estado_id: estadoId,
          },
        });
      } catch (err: any) {
        if (err instanceof ZodError) {
          return reply.code(400).send({
            ok: false,
            message: "Payload inválido",
            detail: zodDetail(err),
          });
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,
            message: "Nombre duplicado",
          });
        }

        req.log.error(
          {
            err,
            id,
          },
          "prevision_medica: error actualizando previsión"
        );

        return reply.code(500).send({
          ok: false,
          message: "Error al actualizar previsión médica",
          detail: err?.message,
        });
      }
    }
  );

  /* ==========================================================
     PATCH /:id
     Edición estructural parcial
     SOLO SUPERADMIN
  ========================================================== */

  app.patch(
    "/:id",
    {
      preHandler: onlySuperadmin,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse(req.params);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      const id = parsed.data.id;

      try {
        const body = PatchSchema.parse(req.body);

        if (Object.keys(body).length === 0) {
          return reply.code(400).send({
            ok: false,
            message: "No hay campos para actualizar",
          });
        }

        const [rows]: any = await db.query(
          `
              SELECT
                id,
                nombre,
                estado_id

              FROM prevision_medica

              WHERE id = ?

              LIMIT 1
            `,
          [id]
        );

        if (!Array.isArray(rows) || !rows.length) {
          return reply.code(404).send({
            ok: false,
            message: "Previsión médica no encontrada",
          });
        }

        const current = rows[0];

        const nombre = body.nombre !== undefined ? body.nombre.trim() : String(current.nombre);

        const estadoId = body.estado_id !== undefined ? body.estado_id : Number(current.estado_id);

        const dup = await existsByNombre(nombre, id);

        if (dup) {
          return reply.code(409).send({
            ok: false,
            message: "Nombre duplicado",
          });
        }

        await db.query(
          `
            UPDATE prevision_medica

            SET
              nombre = ?,
              estado_id = ?

            WHERE id = ?
          `,
          [nombre, estadoId, id]
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          updated: {
            id,
            nombre,
            estado_id: estadoId,
          },
        });
      } catch (err: any) {
        if (err instanceof ZodError) {
          return reply.code(400).send({
            ok: false,
            message: "Payload inválido",
            detail: zodDetail(err),
          });
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,
            message: "Nombre duplicado",
          });
        }

        req.log.error(
          {
            err,
            id,
          },
          "prevision_medica: error PATCH previsión"
        );

        return reply.code(500).send({
          ok: false,
          message: "Error al actualizar previsión médica",
          detail: err?.message,
        });
      }
    }
  );

  /* ==========================================================
     PATCH /:id/disponibilidad

     Activa/desactiva la previsión solamente
     para la academia efectiva.

     Admin / Superadmin
  ========================================================== */

  app.patch(
    "/:id/disponibilidad",
    {
      preHandler: canManageAcademia,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse(req.params);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      const previsionId = parsed.data.id;

      try {
        const body = DisponibilidadSchema.parse(req.body);

        const academiaId = Number(getEffectiveAcademiaId(req));

        if (!Number.isInteger(academiaId) || academiaId <= 0) {
          return reply.code(403).send({
            ok: false,
            message: "No se pudo determinar la academia",
          });
        }

        const [rows]: any = await db.query(
          `
              SELECT
                id,
                estado_id

              FROM prevision_medica

              WHERE id = ?

              LIMIT 1
            `,
          [previsionId]
        );

        if (!Array.isArray(rows) || !rows.length) {
          return reply.code(404).send({
            ok: false,
            message: "Previsión médica no encontrada",
          });
        }

        const estadoGlobal = Number(rows[0].estado_id);

        if (body.estado_id === 1 && estadoGlobal !== 1) {
          return reply.code(409).send({
            ok: false,
            message: "La previsión médica se encuentra deshabilitada globalmente",
          });
        }

        await db.query(
          `
            INSERT INTO academia_prevision_medica (
              academia_id,
              prevision_medica_id,
              estado_id
            )
            VALUES (?, ?, ?)

            ON DUPLICATE KEY UPDATE
              estado_id = ?
          `,
          [academiaId, previsionId, body.estado_id, body.estado_id]
        );

        const item = await getPrevisionById(previsionId, academiaId);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          academia_id: academiaId,

          prevision_medica_id: previsionId,

          estado_academia_id: body.estado_id,

          item,
        });
      } catch (err: any) {
        if (err instanceof ZodError) {
          return reply.code(400).send({
            ok: false,
            message: "Payload inválido",
            detail: zodDetail(err),
          });
        }

        req.log.error(
          {
            err,
            previsionId,
          },
          "prevision_medica: error cambiando disponibilidad"
        );

        return reply.code(err?.statusCode === 403 ? 403 : 500).send({
          ok: false,

          message:
            err?.statusCode === 403
              ? err?.message || "Academia no válida"
              : "Error al actualizar disponibilidad de la previsión médica",

          ...(err?.statusCode !== 403
            ? {
                detail: err?.message,
              }
            : {}),
        });
      }
    }
  );

  /* ==========================================================
     DELETE /:id
     SOLO SUPERADMIN
  ========================================================== */

  app.delete(
    "/:id",
    {
      preHandler: onlySuperadmin,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse(req.params);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      const id = parsed.data.id;

      try {
        const [result]: any = await db.query(
          `
              DELETE
              FROM prevision_medica
              WHERE id = ?
            `,
          [id]
        );

        reply.header("Cache-Control", "no-store");

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,
            message: "Previsión médica no encontrada",
          });
        }

        return reply.send({
          ok: true,
          deleted: id,
        });
      } catch (err: any) {
        const isFk =
          err?.errno === 1451 ||
          err?.code === "ER_ROW_IS_REFERENCED_2" ||
          String(err?.code || "").includes("ER_ROW_IS_REFERENCED");

        if (isFk) {
          return reply.code(409).send({
            ok: false,

            message:
              "No se puede eliminar la previsión médica porque posee registros asociados. Puede deshabilitarla globalmente en su lugar.",

            detail: err?.sqlMessage ?? err?.message,
          });
        }

        req.log.error(
          {
            err,
            id,
          },
          "prevision_medica: error eliminando previsión"
        );

        return reply.code(500).send({
          ok: false,
          message: "Error al eliminar previsión médica",
          detail: err?.message,
        });
      }
    }
  );
}
