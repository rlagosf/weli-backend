// src/routers/establec_educ.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z, ZodError } from "zod";
import { db } from "../db";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * ============================================================
 * ESTABLECIMIENTOS EDUCACIONALES
 * ============================================================
 *
 * Catálogo maestro:
 *   establec_educ
 *
 * Campos:
 *   - id
 *   - nombre
 *   - comuna_id
 *   - estado_id            -> estado GLOBAL
 *   - created_at
 *   - updated_at
 *
 * Relación territorial:
 *
 *   establec_educ
 *        ↓
 *   comunas
 *        ↓
 *   regiones
 *
 * Disponibilidad por academia:
 *
 *   academia_establec_educ
 *
 *   - academia_id
 *   - establecimiento_id
 *   - estado_id            -> estado PARA ESA ACADEMIA
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
    page: z.coerce.number().int().min(1).default(1),

    limit: z.coerce.number().int().min(1).max(100).default(15),

    search: z.string().trim().max(120).optional().default(""),

    region_id: z.coerce.number().int().positive().optional(),

    comuna_id: z.coerce.number().int().positive().optional(),

    estado_id: z.coerce.number().int().min(0).max(1).optional(),

    disponibilidad: z.coerce.number().int().min(0).max(1).optional(),
  })
  .strict();

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(3, "Debe tener al menos 3 caracteres").max(120),

    comuna_id: z.coerce.number().int().positive(),

    estado_id: z.coerce.number().int().min(0).max(1).default(1),
  })
  .strict();

const PutSchema = z
  .object({
    nombre: z.string().trim().min(3, "Debe tener al menos 3 caracteres").max(120),

    comuna_id: z.coerce.number().int().positive(),

    estado_id: z.coerce.number().int().min(0).max(1),
  })
  .strict();

const PatchSchema = z
  .object({
    nombre: z.string().trim().min(3, "Debe tener al menos 3 caracteres").max(120).optional(),

    comuna_id: z.coerce.number().int().positive().optional(),

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
  return err.issues.map((issue) => `${issue.path.join(".") || "field"}: ${issue.message}`).join("; ");
}

function normalize(row: any) {
  const estadoGlobal = Number(row.estado_id ?? 0);

  const estadoAcademia = Number(row.estado_academia_id ?? 0);

  const disponible = estadoGlobal === 1 && estadoAcademia === 1;

  return {
    id: Number(row.id),

    nombre: String(row.nombre ?? ""),

    comuna_id: row.comuna_id !== null && row.comuna_id !== undefined ? Number(row.comuna_id) : null,

    comuna_nombre: row.comuna_nombre !== undefined ? String(row.comuna_nombre ?? "") : "",

    region_id: row.region_id !== null && row.region_id !== undefined ? Number(row.region_id) : null,

    region_nombre: row.region_nombre !== undefined ? String(row.region_nombre ?? "") : "",

    /*
     * Estado maestro/global.
     */
    estado_id: estadoGlobal,
    estado_global_id: estadoGlobal,

    /*
     * Preferencia propia de la academia.
     */
    estado_academia_id: estadoAcademia,

    /*
     * Disponibilidad efectiva:
     *
     * global activo
     * AND
     * academia activa
     */
    disponible,

    created_at: row.created_at ?? null,
    updated_at: row.updated_at ?? null,
  };
}

/**
 * Confirma que una comuna exista.
 */
async function comunaExists(comunaId: number) {
  const [rows]: any = await db.query(
    `
      SELECT id
      FROM comunas
      WHERE id = ?
      LIMIT 1
    `,
    [comunaId]
  );

  return Array.isArray(rows) && rows.length > 0;
}

/**
 * Confirma que un establecimiento exista.
 */
async function establecimientoExists(id: number) {
  const [rows]: any = await db.query(
    `
      SELECT id
      FROM establec_educ
      WHERE id = ?
      LIMIT 1
    `,
    [id]
  );

  return Array.isArray(rows) && rows.length > 0;
}

/**
 * Busca duplicados considerando la restricción real:
 *
 * UNIQUE(comuna_id, nombre)
 */
async function existsByNombreComuna(nombre: string, comunaId: number, excludeId?: number) {
  const value = String(nombre ?? "").trim();

  if (!value) {
    return false;
  }

  if (excludeId) {
    const [rows]: any = await db.query(
      `
        SELECT id
        FROM establec_educ
        WHERE comuna_id = ?
          AND LOWER(TRIM(nombre)) = LOWER(TRIM(?))
          AND id <> ?
        LIMIT 1
      `,
      [comunaId, value, excludeId]
    );

    return Array.isArray(rows) && rows.length > 0;
  }

  const [rows]: any = await db.query(
    `
      SELECT id
      FROM establec_educ
      WHERE comuna_id = ?
        AND LOWER(TRIM(nombre)) = LOWER(TRIM(?))
      LIMIT 1
    `,
    [comunaId, value]
  );

  return Array.isArray(rows) && rows.length > 0;
}

/**
 * Obtiene un establecimiento enriquecido con:
 *
 * - comuna
 * - región
 * - estado global
 * - estado para la academia
 */
async function getEstablecimientoById(id: number, academiaId: number) {
  const [rows]: any = await db.query(
    `
      SELECT
        ee.id,
        ee.nombre,
        ee.comuna_id,
        ee.estado_id,
        ee.created_at,
        ee.updated_at,

        c.nombre AS comuna_nombre,

        r.id AS region_id,
        r.nombre AS region_nombre,

        COALESCE(
          aee.estado_id,
          0
        ) AS estado_academia_id

      FROM establec_educ ee

      INNER JOIN comunas c
        ON c.id = ee.comuna_id

      INNER JOIN regiones r
        ON r.id = c.region_id

      LEFT JOIN academia_establec_educ aee
        ON aee.establecimiento_id = ee.id
       AND aee.academia_id = ?

      WHERE ee.id = ?

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

export default async function establec_educ(app: FastifyInstance) {
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
        module: "establec_educ",
        status: "ready",
        timestamp: new Date().toISOString(),
      };
    }
  );

  /* ==========================================================
     GET /
     Listado paginado
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
        /*
         * Admin / Staff:
         *   academia desde JWT.
         *
         * Superadmin:
         *   academia desde x-academia-id.
         */
        const academiaId = Number(getEffectiveAcademiaId(req));

        if (!Number.isInteger(academiaId) || academiaId <= 0) {
          return reply.code(403).send({
            ok: false,
            message: "No se pudo determinar la academia",
          });
        }

        const { page, limit, search, region_id, comuna_id, estado_id, disponibilidad } = parsed.data;

        const offset = (page - 1) * limit;

        const normalizedSearch = search.trim();

        /*
         * WHERE dinámico.
         */
        const conditions: string[] = [];

        const whereParams: any[] = [];

        if (normalizedSearch) {
          conditions.push(
            `
              (
                LOWER(ee.nombre)
                  LIKE LOWER(?)

                OR LOWER(c.nombre)
                  LIKE LOWER(?)

                OR LOWER(r.nombre)
                  LIKE LOWER(?)
              )
            `
          );

          const value = `%${normalizedSearch}%`;

          whereParams.push(value, value, value);
        }

        if (region_id !== undefined) {
          conditions.push("r.id = ?");

          whereParams.push(region_id);
        }

        if (comuna_id !== undefined) {
          conditions.push("c.id = ?");

          whereParams.push(comuna_id);
        }

        if (estado_id !== undefined) {
          conditions.push("ee.estado_id = ?");

          whereParams.push(estado_id);
        }

        /*
         * disponibilidad representa disponibilidad
         * EFECTIVA.
         *
         * 1:
         *   estado global = 1
         *   estado academia = 1
         *
         * 0:
         *   cualquier otro escenario
         */
        if (disponibilidad !== undefined) {
          conditions.push(
            `
              CASE
                WHEN ee.estado_id = 1
                 AND COALESCE(
                       aee.estado_id,
                       0
                     ) = 1
                THEN 1
                ELSE 0
              END = ?
            `
          );

          whereParams.push(disponibilidad);
        }

        const whereSql = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

        /*
         * El primer parámetro siempre corresponde
         * al academia_id usado por el LEFT JOIN.
         */
        const baseParams = [academiaId, ...whereParams];

        const [countRows]: any = await db.query(
          `
              SELECT
                COUNT(*) AS total

              FROM establec_educ ee

              INNER JOIN comunas c
                ON c.id = ee.comuna_id

              INNER JOIN regiones r
                ON r.id = c.region_id

              LEFT JOIN academia_establec_educ aee
                ON aee.establecimiento_id = ee.id
               AND aee.academia_id = ?

              ${whereSql}
            `,
          baseParams
        );

        const total = Number(countRows?.[0]?.total ?? 0);

        const totalPages = Math.max(1, Math.ceil(total / limit));

        const [rows]: any = await db.query(
          `
              SELECT
                ee.id,
                ee.nombre,
                ee.comuna_id,
                ee.estado_id,
                ee.created_at,
                ee.updated_at,

                c.nombre
                  AS comuna_nombre,

                r.id
                  AS region_id,

                r.nombre
                  AS region_nombre,

                COALESCE(
                  aee.estado_id,
                  0
                ) AS estado_academia_id

              FROM establec_educ ee

              INNER JOIN comunas c
                ON c.id = ee.comuna_id

              INNER JOIN regiones r
                ON r.id = c.region_id

              LEFT JOIN academia_establec_educ aee
                ON aee.establecimiento_id = ee.id
               AND aee.academia_id = ?

              ${whereSql}

              ORDER BY
                r.nombre ASC,
                c.nombre ASC,
                ee.nombre ASC,
                ee.id ASC

              LIMIT ?
              OFFSET ?
            `,
          [...baseParams, limit, offset]
        );

        const items = (rows || []).map(normalize);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          items,

          pagination: {
            page,
            limit,
            total,
            total_pages: totalPages,
            has_previous: page > 1,
            has_next: page < totalPages,
          },

          summary: {
            total,
          },
        });
      } catch (err: any) {
        req.log.error(
          {
            err,
          },
          "establec_educ: error listando establecimientos"
        );

        return reply.code(err?.statusCode === 403 ? 403 : 500).send({
          ok: false,

          message: err?.statusCode === 403 ? err?.message || "Academia no válida" : "Error al listar establecimientos",

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

        const item = await getEstablecimientoById(id, academiaId);

        reply.header("Cache-Control", "no-store");

        if (!item) {
          return reply.code(404).send({
            ok: false,
            message: "Establecimiento no encontrado",
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
          "establec_educ: error obteniendo establecimiento"
        );

        return reply.code(err?.statusCode === 403 ? 403 : 500).send({
          ok: false,

          message: err?.statusCode === 403 ? err?.message || "Academia no válida" : "Error al obtener establecimiento",

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
     Crear establecimiento global
     SOLO SUPERADMIN
  ========================================================== */

  app.post(
    "/",
    {
      preHandler: onlySuperadmin,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const parsed = CreateSchema.parse(req.body);

        const nombre = parsed.nombre.trim();

        const comunaId = parsed.comuna_id;

        const estadoId = parsed.estado_id;

        /*
         * Validar comuna.
         */
        const validComuna = await comunaExists(comunaId);

        if (!validComuna) {
          return reply.code(400).send({
            ok: false,
            message: "La comuna indicada no existe",
          });
        }

        /*
         * La unicidad ahora es:
         *
         * comuna_id + nombre
         */
        const duplicate = await existsByNombreComuna(nombre, comunaId);

        if (duplicate) {
          return reply.code(409).send({
            ok: false,
            message: "Ya existe un establecimiento con ese nombre en la comuna seleccionada",
          });
        }

        const [result]: any = await db.query(
          `
              INSERT INTO establec_educ (
                nombre,
                comuna_id,
                estado_id
              )
              VALUES (?, ?, ?)
            `,
          [nombre, comunaId, estadoId]
        );

        const id = Number(result.insertId);

        reply.header("Cache-Control", "no-store");

        return reply.code(201).send({
          ok: true,

          id,

          item: {
            id,
            nombre,
            comuna_id: comunaId,
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
            message: "Ya existe un establecimiento con ese nombre en la comuna seleccionada",
          });
        }

        req.log.error(
          {
            err,
          },
          "establec_educ: error creando establecimiento"
        );

        return reply.code(500).send({
          ok: false,
          message: "Error al crear establecimiento",
          detail: err?.message,
        });
      }
    }
  );

  /* ==========================================================
     PUT /:id
     Sustitución completa estructural
     SOLO SUPERADMIN
  ========================================================== */

  app.put(
    "/:id",
    {
      preHandler: onlySuperadmin,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsedId = IdParam.safeParse(req.params);

      if (!parsedId.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      const id = parsedId.data.id;

      try {
        const body = PutSchema.parse(req.body);

        const exists = await establecimientoExists(id);

        if (!exists) {
          return reply.code(404).send({
            ok: false,
            message: "Establecimiento no encontrado",
          });
        }

        const nombre = body.nombre.trim();

        const comunaId = body.comuna_id;

        const estadoId = body.estado_id;

        const validComuna = await comunaExists(comunaId);

        if (!validComuna) {
          return reply.code(400).send({
            ok: false,
            message: "La comuna indicada no existe",
          });
        }

        const duplicate = await existsByNombreComuna(nombre, comunaId, id);

        if (duplicate) {
          return reply.code(409).send({
            ok: false,
            message: "Ya existe un establecimiento con ese nombre en la comuna seleccionada",
          });
        }

        await db.query(
          `
            UPDATE establec_educ

            SET
              nombre = ?,
              comuna_id = ?,
              estado_id = ?

            WHERE id = ?
          `,
          [nombre, comunaId, estadoId, id]
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          updated: {
            id,
            nombre,
            comuna_id: comunaId,
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
            message: "Ya existe un establecimiento con ese nombre en la comuna seleccionada",
          });
        }

        req.log.error(
          {
            err,
            id,
          },
          "establec_educ: error actualizando establecimiento"
        );

        return reply.code(500).send({
          ok: false,
          message: "Error al actualizar establecimiento",
          detail: err?.message,
        });
      }
    }
  );

  /* ==========================================================
     PATCH /:id
     Edición parcial estructural
     SOLO SUPERADMIN
  ========================================================== */

  app.patch(
    "/:id",
    {
      preHandler: onlySuperadmin,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsedId = IdParam.safeParse(req.params);

      if (!parsedId.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      const id = parsedId.data.id;

      try {
        const body = PatchSchema.parse(req.body);

        if (Object.keys(body).length === 0) {
          return reply.code(400).send({
            ok: false,
            message: "No hay campos para actualizar",
          });
        }

        /*
         * Necesitamos la fila actual porque
         * nombre y comuna forman juntos
         * la restricción UNIQUE.
         */
        const [currentRows]: any = await db.query(
          `
              SELECT
                id,
                nombre,
                comuna_id,
                estado_id

              FROM establec_educ

              WHERE id = ?

              LIMIT 1
            `,
          [id]
        );

        if (!Array.isArray(currentRows) || !currentRows.length) {
          return reply.code(404).send({
            ok: false,
            message: "Establecimiento no encontrado",
          });
        }

        const current = currentRows[0];

        const nombre = body.nombre !== undefined ? body.nombre.trim() : String(current.nombre);

        const comunaId = body.comuna_id !== undefined ? body.comuna_id : Number(current.comuna_id);

        const estadoId = body.estado_id !== undefined ? body.estado_id : Number(current.estado_id);

        const validComuna = await comunaExists(comunaId);

        if (!validComuna) {
          return reply.code(400).send({
            ok: false,
            message: "La comuna indicada no existe",
          });
        }

        const duplicate = await existsByNombreComuna(nombre, comunaId, id);

        if (duplicate) {
          return reply.code(409).send({
            ok: false,
            message: "Ya existe un establecimiento con ese nombre en la comuna seleccionada",
          });
        }

        await db.query(
          `
            UPDATE establec_educ

            SET
              nombre = ?,
              comuna_id = ?,
              estado_id = ?

            WHERE id = ?
          `,
          [nombre, comunaId, estadoId, id]
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          updated: {
            id,
            nombre,
            comuna_id: comunaId,
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
            message: "Ya existe un establecimiento con ese nombre en la comuna seleccionada",
          });
        }

        req.log.error(
          {
            err,
            id,
          },
          "establec_educ: error PATCH establecimiento"
        );

        return reply.code(500).send({
          ok: false,
          message: "Error al actualizar establecimiento",
          detail: err?.message,
        });
      }
    }
  );

  /* ==========================================================
     PATCH /:id/disponibilidad

     Habilitar / deshabilitar un establecimiento
     exclusivamente para la academia efectiva.

     Admin / Superadmin.

     NO modifica:
       establec_educ.estado_id

     Modifica:
       academia_establec_educ.estado_id
  ========================================================== */

  app.patch(
    "/:id/disponibilidad",
    {
      preHandler: canManageAcademia,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsedId = IdParam.safeParse(req.params);

      if (!parsedId.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      const establecimientoId = parsedId.data.id;

      try {
        const body = DisponibilidadSchema.parse(req.body);

        const academiaId = Number(getEffectiveAcademiaId(req));

        if (!Number.isInteger(academiaId) || academiaId <= 0) {
          return reply.code(403).send({
            ok: false,
            message: "No se pudo determinar la academia",
          });
        }

        /*
         * Verificamos también el estado global.
         */
        const [rows]: any = await db.query(
          `
              SELECT
                id,
                estado_id

              FROM establec_educ

              WHERE id = ?

              LIMIT 1
            `,
          [establecimientoId]
        );

        if (!Array.isArray(rows) || !rows.length) {
          return reply.code(404).send({
            ok: false,
            message: "Establecimiento no encontrado",
          });
        }

        const estadoGlobal = Number(rows[0].estado_id);

        /*
         * Una academia no puede habilitar
         * un establecimiento deshabilitado
         * globalmente por Superadmin.
         */
        if (body.estado_id === 1 && estadoGlobal !== 1) {
          return reply.code(409).send({
            ok: false,
            message: "El establecimiento se encuentra deshabilitado globalmente",
          });
        }

        /*
         * Upsert:
         *
         * si no existe relación -> INSERT
         * si existe             -> UPDATE estado
         */
        await db.query(
          `
            INSERT INTO academia_establec_educ (
              academia_id,
              establecimiento_id,
              estado_id
            )
            VALUES (?, ?, ?)

            ON DUPLICATE KEY UPDATE
              estado_id = ?
          `,
          [academiaId, establecimientoId, body.estado_id, body.estado_id]
        );

        const item = await getEstablecimientoById(establecimientoId, academiaId);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          academia_id: academiaId,

          establecimiento_id: establecimientoId,

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
            establecimientoId,
          },
          "establec_educ: error cambiando disponibilidad"
        );

        return reply.code(err?.statusCode === 403 ? 403 : 500).send({
          ok: false,

          message:
            err?.statusCode === 403
              ? err?.message || "Academia no válida"
              : "Error al actualizar disponibilidad del establecimiento",

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
              FROM establec_educ
              WHERE id = ?
            `,
          [id]
        );

        reply.header("Cache-Control", "no-store");

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,
            message: "Establecimiento no encontrado",
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
              "No se puede eliminar el establecimiento porque posee relaciones asociadas. Puede deshabilitarlo globalmente en su lugar.",

            detail: err?.sqlMessage ?? err?.message,
          });
        }

        req.log.error(
          {
            err,
            id,
          },
          "establec_educ: error eliminando establecimiento"
        );

        return reply.code(500).send({
          ok: false,
          message: "Error al eliminar establecimiento",
          detail: err?.message,
        });
      }
    }
  );
}
