import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z, ZodError } from "zod";

import { db } from "../db";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * ============================================================
 * WELI - TIPOS DE PAGO
 * ============================================================
 *
 * tipo_pago
 * ------------------------------------------------------------
 * Catálogo GLOBAL.
 *
 * Ejemplos:
 * - Matrícula
 * - Mantención
 * - Material deportivo
 * - Torneo
 * - Seguro
 *
 * Solo Superadmin administra estructuralmente este catálogo.
 *
 *
 * academia_tipo_pago
 * ------------------------------------------------------------
 * Define qué tipos de pago utiliza cada academia.
 *
 * La ausencia de relación significa:
 * - NO habilitado para esa academia.
 *
 *
 * tarifas_academia
 * ------------------------------------------------------------
 * Define el monto configurado por una academia para un
 * tipo de pago habilitado.
 *
 * Puede contener múltiples versiones históricas.
 *
 * La tarifa actualmente vigente se identifica mediante:
 *
 *   es_vigente = 1
 *
 *
 * SEGURIDAD
 * ------------------------------------------------------------
 *
 * Admin:
 * - academia desde JWT firmado.
 * - puede consultar catálogo efectivo.
 * - puede consultar configuración.
 * - puede habilitar/deshabilitar tipos para su academia.
 * - NO modifica tipo_pago global.
 *
 * Superadmin:
 * - academia desde x-academia-id para operaciones scoped.
 * - administra catálogo global.
 *
 * academia_id:
 * - NUNCA se recibe desde el body.
 * ============================================================
 */

/* ============================================================
   SCHEMAS
============================================================ */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const EstadoSchema = z.coerce.number().int().min(0).max(1);

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres").max(100, "Máximo 100 caracteres"),

    descripcion: z.string().trim().max(255, "Máximo 255 caracteres").nullable().optional(),

    estado_id: EstadoSchema.default(1),
  })
  .strict();

const PutSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres").max(100, "Máximo 100 caracteres"),

    descripcion: z.string().trim().max(255, "Máximo 255 caracteres").nullable(),

    estado_id: EstadoSchema,
  })
  .strict();

const PatchSchema = z
  .object({
    nombre: z
      .string()
      .trim()
      .min(3, "El nombre debe tener al menos 3 caracteres")
      .max(100, "Máximo 100 caracteres")
      .optional(),

    descripcion: z.string().trim().max(255, "Máximo 255 caracteres").nullable().optional(),

    estado_id: EstadoSchema.optional(),
  })
  .strict();

const DisponibilidadSchema = z
  .object({
    estado_id: EstadoSchema,
  })
  .strict();

const ConfiguracionQuerySchema = z
  .object({
    search: z.string().trim().max(120).optional().default(""),

    estado_academia_id: EstadoSchema.optional(),
  })
  .strict();

/* ============================================================
   HELPERS GENERALES
============================================================ */

function normalizeName(value: string): string {
  return String(value ?? "")
    .trim()
    .replace(/\s+/g, " ");
}

function normalizeDescription(value: unknown): string | null {
  if (value === null || value === undefined) {
    return null;
  }

  const normalized = String(value).trim().replace(/\s+/g, " ");

  return normalized || null;
}

function zodDetail(err: ZodError): string {
  return err.issues.map((issue) => `${issue.path.join(".") || "field"}: ${issue.message}`).join("; ");
}

/* ============================================================
   ACADEMIA EFECTIVA
============================================================ */

function resolveAcademiaId(req: FastifyRequest): number {
  const academiaId = Number(getEffectiveAcademiaId(req));

  if (!Number.isInteger(academiaId) || academiaId <= 0) {
    const err: any = new Error("Academia efectiva inválida");

    err.statusCode = 403;

    throw err;
  }

  return academiaId;
}

/* ============================================================
   NORMALIZACIÓN GLOBAL
============================================================ */

function normalizeGlobal(row: any) {
  return {
    id: Number(row.id),

    nombre: String(row.nombre ?? ""),

    descripcion: row.descripcion == null ? null : String(row.descripcion),

    estado_id: Number(row.estado_id),
  };
}

/* ============================================================
   NORMALIZACIÓN CONFIGURACIÓN ACADEMIA
============================================================ */

function normalizeConfiguration(row: any) {
  const estadoGlobal = Number(row.estado_global_id ?? row.estado_id ?? 0);

  const estadoAcademia = Number(row.estado_academia_id ?? 0);

  const disponible = estadoGlobal === 1 && estadoAcademia === 1;

  return {
    id: Number(row.id),

    tipo_pago_id: Number(row.id),

    nombre: String(row.nombre ?? ""),

    descripcion: row.descripcion == null ? null : String(row.descripcion),

    /*
     * Estado global.
     */
    estado_id: estadoGlobal,

    estado_global_id: estadoGlobal,

    /*
     * Relación con academia.
     */
    academia_tipo_pago_id: row.academia_tipo_pago_id == null ? null : Number(row.academia_tipo_pago_id),

    academia_id: row.academia_id == null ? null : Number(row.academia_id),

    estado_academia_id: estadoAcademia,

    disponible,

    /*
     * Tarifa actualmente vigente.
     */
    tarifa_id: row.tarifa_id == null ? null : Number(row.tarifa_id),

    monto: row.monto == null ? null : Number(row.monto),

    tarifa_estado_id: row.tarifa_estado_id == null ? null : Number(row.tarifa_estado_id),

    tarifa_vigencia_desde: row.tarifa_vigencia_desde ?? null,

    tarifa_vigencia_hasta: row.tarifa_vigencia_hasta ?? null,

    tarifa_es_vigente: row.tarifa_es_vigente == null ? null : Number(row.tarifa_es_vigente),
  };
}

/* ============================================================
   NORMALIZACIÓN CATÁLOGO EFECTIVO
============================================================ */

function normalizeScoped(row: any) {
  return {
    id: Number(row.id),

    tipo_pago_id: Number(row.id),

    nombre: String(row.nombre ?? ""),

    descripcion: row.descripcion == null ? null : String(row.descripcion),

    estado_id: Number(row.estado_id),

    estado_global_id: Number(row.estado_id),

    academia_tipo_pago_id: Number(row.academia_tipo_pago_id),

    academia_id: Number(row.academia_id),

    estado_academia_id: Number(row.academia_estado_id),

    disponible: Number(row.estado_id) === 1 && Number(row.academia_estado_id) === 1,

    tarifa_id: row.tarifa_id == null ? null : Number(row.tarifa_id),

    monto: row.monto == null ? null : Number(row.monto),

    tarifa_estado_id: row.tarifa_estado_id == null ? null : Number(row.tarifa_estado_id),

    tarifa_vigencia_desde: row.tarifa_vigencia_desde ?? null,

    tarifa_vigencia_hasta: row.tarifa_vigencia_hasta ?? null,

    tarifa_es_vigente: row.tarifa_es_vigente == null ? null : Number(row.tarifa_es_vigente),
  };
}

/* ============================================================
   DUPLICADOS GLOBALES
============================================================ */

async function existsByNombre(nombre: string, excludeId?: number): Promise<boolean> {
  const normalized = normalizeName(nombre);

  if (!normalized) {
    return false;
  }

  if (excludeId !== undefined) {
    const [rows]: any = await db.query(
      `
          SELECT
            id

          FROM tipo_pago

          WHERE LOWER(
                  TRIM(nombre)
                ) = LOWER(?)

            AND id <> ?

          LIMIT 1
        `,
      [normalized, excludeId]
    );

    return Array.isArray(rows) && rows.length > 0;
  }

  const [rows]: any = await db.query(
    `
        SELECT
          id

        FROM tipo_pago

        WHERE LOWER(
                TRIM(nombre)
              ) = LOWER(?)

        LIMIT 1
      `,
    [normalized]
  );

  return Array.isArray(rows) && rows.length > 0;
}

/* ============================================================
   OBTENER GLOBAL
============================================================ */

async function getGlobalById(id: number) {
  const [rows]: any = await db.query(
    `
        SELECT
          id,
          nombre,
          descripcion,
          estado_id

        FROM tipo_pago

        WHERE id = ?

        LIMIT 1
      `,
    [id]
  );

  return rows?.length ? rows[0] : null;
}

/* ============================================================
   OBTENER CONFIGURACIÓN DE ACADEMIA
============================================================ */

async function getConfigurationById(academiaId: number, tipoPagoId: number) {
  const [rows]: any = await db.query(
    `
        SELECT
          tp.id,
          tp.nombre,
          tp.descripcion,

          tp.estado_id
            AS estado_global_id,

          atp.id
            AS academia_tipo_pago_id,

          atp.academia_id,

          COALESCE(
            atp.estado_id,
            0
          ) AS estado_academia_id,

          ta.id
            AS tarifa_id,

          ta.monto,

          ta.estado_id
            AS tarifa_estado_id,

          ta.vigencia_desde
            AS tarifa_vigencia_desde,

          ta.vigencia_hasta
            AS tarifa_vigencia_hasta,

          ta.es_vigente
            AS tarifa_es_vigente

        FROM tipo_pago tp

        LEFT JOIN academia_tipo_pago atp
          ON atp.tipo_pago_id =
             tp.id

         AND atp.academia_id = ?

        LEFT JOIN tarifas_academia ta
          ON ta.academia_id = ?

         AND ta.tipo_pago_id =
             tp.id

         AND ta.es_vigente = 1

        WHERE tp.id = ?

        LIMIT 1
      `,
    [academiaId, academiaId, tipoPagoId]
  );

  return rows?.length ? rows[0] : null;
}

/* ============================================================
   OBTENER TIPO EFECTIVO DE ACADEMIA
============================================================ */

async function getScopedById(academiaId: number, tipoPagoId: number) {
  const [rows]: any = await db.query(
    `
        SELECT
          tp.id,
          tp.nombre,
          tp.descripcion,
          tp.estado_id,

          atp.id
            AS academia_tipo_pago_id,

          atp.academia_id,

          atp.estado_id
            AS academia_estado_id,

          ta.id
            AS tarifa_id,

          ta.monto,

          ta.estado_id
            AS tarifa_estado_id,

          ta.vigencia_desde
            AS tarifa_vigencia_desde,

          ta.vigencia_hasta
            AS tarifa_vigencia_hasta,

          ta.es_vigente
            AS tarifa_es_vigente

        FROM tipo_pago tp

        INNER JOIN academia_tipo_pago atp
          ON atp.tipo_pago_id =
             tp.id

         AND atp.academia_id = ?

        LEFT JOIN tarifas_academia ta
          ON ta.academia_id =
             atp.academia_id

         AND ta.tipo_pago_id =
             atp.tipo_pago_id

         AND ta.es_vigente = 1

        WHERE tp.id = ?

        LIMIT 1
      `,
    [academiaId, tipoPagoId]
  );

  return rows?.length ? rows[0] : null;
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

      message: "Ya existe un registro equivalente",
    });
  }

  if (
    err?.errno === 1451 ||
    err?.code === "ER_ROW_IS_REFERENCED_2" ||
    String(err?.code ?? "").includes("ER_ROW_IS_REFERENCED")
  ) {
    return reply.code(409).send({
      ok: false,

      message: "No se puede eliminar el tipo de pago porque posee información relacionada",
    });
  }

  console.error(`[tipo_pago] ${operation}`, err);

  return reply.code(500).send({
    ok: false,

    message: `Error al ${operation} tipo de pago`,

    detail: err?.message,
  });
}

/* ============================================================
   ROUTER
============================================================ */

export default async function tipo_pago(app: FastifyInstance) {
  /*
   * Operación dentro de una academia.
   */
  const canManageScoped = [requireAuth, requireRoles([1, 3])];

  /*
   * Administración catálogo global.
   */
  const onlySuper = [requireAuth, requireRoles([3])];

  /* ==========================================================
     HEALTH
  ========================================================== */

  app.get(
    "/health",
    {
      preHandler: canManageScoped,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const academiaId = resolveAcademiaId(req);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          module: "tipo_pago",

          status: "ready",

          scope: "academia",

          academia_id: academiaId,

          timestamp: new Date().toISOString(),
        });
      } catch (err: any) {
        return handleDatabaseError(reply, err, "consultar");
      }
    }
  );

  /* ==========================================================
     GET /catalogo

     CATÁLOGO GLOBAL
     SOLO SUPERADMIN
  ========================================================== */

  app.get(
    "/catalogo",
    {
      preHandler: onlySuper,
    },
    async (_req: FastifyRequest, reply: FastifyReply) => {
      try {
        const [rows]: any = await db.query(
          `
              SELECT
                id,
                nombre,
                descripcion,
                estado_id

              FROM tipo_pago

              ORDER BY
                nombre ASC,
                id ASC
            `
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          scope: "global",

          count: rows?.length ?? 0,

          items: (rows ?? []).map(normalizeGlobal),
        });
      } catch (err: any) {
        return handleDatabaseError(reply, err, "listar catálogo global de");
      }
    }
  );

  /* ==========================================================
     GET /configuracion

     CATÁLOGO COMPLETO + CONFIGURACIÓN DE LA ACADEMIA

     Admin / Superadmin

     Esta es la ruta destinada al frontend de configuración.
  ========================================================== */

  app.get(
    "/configuracion",
    {
      preHandler: canManageScoped,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = ConfiguracionQuerySchema.safeParse(req.query);

      if (!parsed.success) {
        reply.header("Cache-Control", "no-store");

        return reply.code(400).send({
          ok: false,

          message: "Parámetros inválidos",

          detail: zodDetail(parsed.error),
        });
      }

      try {
        const academiaId = resolveAcademiaId(req);

        const { search, estado_academia_id } = parsed.data;

        const where: string[] = [];

        const values: any[] = [academiaId, academiaId];

        if (search) {
          where.push(
            `
              (
                LOWER(tp.nombre)
                  LIKE LOWER(?)

                OR LOWER(
                     COALESCE(
                       tp.descripcion,
                       ''
                     )
                   )
                  LIKE LOWER(?)

                OR CAST(
                     tp.id AS CHAR
                   )
                  LIKE ?
              )
            `
          );

          const term = `%${search}%`;

          values.push(term, term, term);
        }

        if (estado_academia_id !== undefined) {
          where.push(
            `
              COALESCE(
                atp.estado_id,
                0
              ) = ?
            `
          );

          values.push(estado_academia_id);
        }

        const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

        const [rows]: any = await db.query(
          `
              SELECT
                tp.id,
                tp.nombre,
                tp.descripcion,

                tp.estado_id
                  AS estado_global_id,

                atp.id
                  AS academia_tipo_pago_id,

                atp.academia_id,

                COALESCE(
                  atp.estado_id,
                  0
                ) AS estado_academia_id,

                ta.id
                  AS tarifa_id,

                ta.monto,

                ta.estado_id
                  AS tarifa_estado_id,

                ta.vigencia_desde
                  AS tarifa_vigencia_desde,

                ta.vigencia_hasta
                  AS tarifa_vigencia_hasta,

                ta.es_vigente
                  AS tarifa_es_vigente

              FROM tipo_pago tp

              LEFT JOIN academia_tipo_pago atp
                ON atp.tipo_pago_id =
                   tp.id

               AND atp.academia_id = ?

              LEFT JOIN tarifas_academia ta
                ON ta.academia_id = ?

               AND ta.tipo_pago_id =
                   tp.id

               AND ta.es_vigente = 1

              ${whereSql}

              ORDER BY
                tp.nombre ASC,
                tp.id ASC
            `,
          values
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          scope: "configuracion",

          academia_id: academiaId,

          count: rows?.length ?? 0,

          items: (rows ?? []).map(normalizeConfiguration),
        });
      } catch (err: any) {
        return handleDatabaseError(reply, err, "listar configuración de");
      }
    }
  );

  /* ==========================================================
     PATCH /:id/disponibilidad

     HABILITAR / DESHABILITAR TIPO DE PAGO
     PARA UNA ACADEMIA

     NO modifica tipo_pago global.
  ========================================================== */

  app.patch(
    "/:id/disponibilidad",
    {
      preHandler: canManageScoped,
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

        const tipoPagoId = parsedId.data.id;

        const body = DisponibilidadSchema.parse(req.body);

        const global = await getGlobalById(tipoPagoId);

        if (!global) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Tipo de pago no encontrado",
          });
        }

        /*
         * No se puede activar dentro de una academia
         * un concepto globalmente deshabilitado.
         */
        if (body.estado_id === 1 && Number(global.estado_id) !== 1) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "El tipo de pago se encuentra deshabilitado globalmente",
          });
        }

        /*
         * UPSERT.
         *
         * academia_tipo_pago posee:
         *
         * UNIQUE (
         *   academia_id,
         *   tipo_pago_id
         * )
         */
        await db.query(
          `
            INSERT INTO academia_tipo_pago (
              academia_id,
              tipo_pago_id,
              estado_id
            )

            VALUES (?, ?, ?)

            ON DUPLICATE KEY UPDATE
              estado_id =
                VALUES(
                  estado_id
                )
          `,
          [academiaId, tipoPagoId, body.estado_id]
        );

        const row = await getConfigurationById(academiaId, tipoPagoId);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          academia_id: academiaId,

          tipo_pago_id: tipoPagoId,

          estado_academia_id: body.estado_id,

          item: row ? normalizeConfiguration(row) : null,
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

        return handleDatabaseError(reply, err, "actualizar disponibilidad de");
      }
    }
  );

  /* ==========================================================
     GET /

     CATÁLOGO EFECTIVO DE LA ACADEMIA

     Devuelve SOLAMENTE:
     - tipo global activo
     - relación academia activa

     Es la ruta adecuada para formularios operativos.
  ========================================================== */

  app.get(
    "/",
    {
      preHandler: canManageScoped,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const academiaId = resolveAcademiaId(req);

        const [rows]: any = await db.query(
          `
              SELECT
                tp.id,
                tp.nombre,
                tp.descripcion,
                tp.estado_id,

                atp.id
                  AS academia_tipo_pago_id,

                atp.academia_id,

                atp.estado_id
                  AS academia_estado_id,

                ta.id
                  AS tarifa_id,

                ta.monto,

                ta.estado_id
                  AS tarifa_estado_id,

                ta.vigencia_desde
                  AS tarifa_vigencia_desde,

                ta.vigencia_hasta
                  AS tarifa_vigencia_hasta,

                ta.es_vigente
                  AS tarifa_es_vigente

              FROM academia_tipo_pago atp

              INNER JOIN tipo_pago tp
                ON tp.id =
                   atp.tipo_pago_id

              LEFT JOIN tarifas_academia ta
                ON ta.academia_id =
                   atp.academia_id

               AND ta.tipo_pago_id =
                   atp.tipo_pago_id

               AND ta.es_vigente = 1

              WHERE atp.academia_id = ?

                AND atp.estado_id = 1

                AND tp.estado_id = 1

              ORDER BY
                tp.nombre ASC,
                tp.id ASC
            `,
          [academiaId]
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          scope: "academia",

          academia_id: academiaId,

          count: rows?.length ?? 0,

          items: (rows ?? []).map(normalizeScoped),
        });
      } catch (err: any) {
        return handleDatabaseError(reply, err, "listar");
      }
    }
  );

  /* ==========================================================
     GET /:id

     TIPO DE PAGO EFECTIVAMENTE HABILITADO
     EN LA ACADEMIA
  ========================================================== */

  app.get(
    "/:id",
    {
      preHandler: canManageScoped,
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

        const row = await getScopedById(academiaId, parsed.data.id);

        reply.header("Cache-Control", "no-store");

        if (!row) {
          return reply.code(404).send({
            ok: false,

            message: "El tipo de pago no está habilitado para esta academia",
          });
        }

        if (Number(row.academia_estado_id) !== 1 || Number(row.estado_id) !== 1) {
          return reply.code(404).send({
            ok: false,

            message: "El tipo de pago no está habilitado para esta academia",
          });
        }

        return reply.send({
          ok: true,

          academia_id: academiaId,

          item: normalizeScoped(row),
        });
      } catch (err: any) {
        return handleDatabaseError(reply, err, "obtener");
      }
    }
  );

  /* ==========================================================
     POST /

     CREAR TIPO DE PAGO GLOBAL
     SOLO SUPERADMIN
  ========================================================== */

  app.post(
    "/",
    {
      preHandler: onlySuper,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const body = CreateSchema.parse(req.body);

        const nombre = normalizeName(body.nombre);

        const descripcion = normalizeDescription(body.descripcion);

        const estadoId = Number(body.estado_id);

        const duplicate = await existsByNombre(nombre);

        if (duplicate) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "Ya existe un tipo de pago con ese nombre",
          });
        }

        const [result]: any = await db.query(
          `
              INSERT INTO tipo_pago (
                nombre,
                descripcion,
                estado_id
              )

              VALUES (?, ?, ?)
            `,
          [nombre, descripcion, estadoId]
        );

        const insertId = Number(result?.insertId);

        const row = await getGlobalById(insertId);

        reply.header("Cache-Control", "no-store");

        return reply.code(201).send({
          ok: true,

          id: insertId,

          item: row
            ? normalizeGlobal(row)
            : {
                id: insertId,

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

            message: "Datos inválidos",

            detail: zodDetail(err),
          });
        }

        return handleDatabaseError(reply, err, "crear");
      }
    }
  );

  /* ==========================================================
     PUT /:id

     REEMPLAZO GLOBAL
     SOLO SUPERADMIN
  ========================================================== */

  app.put(
    "/:id",
    {
      preHandler: onlySuper,
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
        const id = parsed.data.id;

        const body = PutSchema.parse(req.body);

        const current = await getGlobalById(id);

        if (!current) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Tipo de pago no encontrado",
          });
        }

        const nombre = normalizeName(body.nombre);

        const descripcion = normalizeDescription(body.descripcion);

        const estadoId = Number(body.estado_id);

        const duplicate = await existsByNombre(nombre, id);

        if (duplicate) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "Ya existe un tipo de pago con ese nombre",
          });
        }

        await db.query(
          `
            UPDATE tipo_pago

            SET
              nombre = ?,
              descripcion = ?,
              estado_id = ?

            WHERE id = ?

            LIMIT 1
          `,
          [nombre, descripcion, estadoId, id]
        );

        const updated = await getGlobalById(id);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          updated: updated
            ? normalizeGlobal(updated)
            : {
                id,
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

            message: "Datos inválidos",

            detail: zodDetail(err),
          });
        }

        return handleDatabaseError(reply, err, "actualizar");
      }
    }
  );

  /* ==========================================================
     PATCH /:id

     ACTUALIZACIÓN GLOBAL PARCIAL
     SOLO SUPERADMIN
  ========================================================== */

  app.patch(
    "/:id",
    {
      preHandler: onlySuper,
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
        const id = parsed.data.id;

        const body = PatchSchema.parse(req.body);

        if (Object.keys(body).length === 0) {
          reply.header("Cache-Control", "no-store");

          return reply.code(400).send({
            ok: false,

            message: "No hay campos para actualizar",
          });
        }

        const current = await getGlobalById(id);

        if (!current) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Tipo de pago no encontrado",
          });
        }

        const nombre = body.nombre !== undefined ? normalizeName(body.nombre) : String(current.nombre);

        const descripcion =
          body.descripcion !== undefined
            ? normalizeDescription(body.descripcion)
            : normalizeDescription(current.descripcion);

        const estadoId = body.estado_id !== undefined ? Number(body.estado_id) : Number(current.estado_id);

        if (body.nombre !== undefined) {
          const duplicate = await existsByNombre(nombre, id);

          if (duplicate) {
            reply.header("Cache-Control", "no-store");

            return reply.code(409).send({
              ok: false,

              message: "Ya existe un tipo de pago con ese nombre",
            });
          }
        }

        await db.query(
          `
            UPDATE tipo_pago

            SET
              nombre = ?,
              descripcion = ?,
              estado_id = ?

            WHERE id = ?

            LIMIT 1
          `,
          [nombre, descripcion, estadoId, id]
        );

        const updated = await getGlobalById(id);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          updated: updated
            ? normalizeGlobal(updated)
            : {
                id,
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

            message: "Datos inválidos",

            detail: zodDetail(err),
          });
        }

        return handleDatabaseError(reply, err, "actualizar");
      }
    }
  );

  /* ==========================================================
     DELETE /:id

     ELIMINACIÓN GLOBAL
     SOLO SUPERADMIN
  ========================================================== */

  app.delete(
    "/:id",
    {
      preHandler: onlySuper,
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
        const id = parsed.data.id;

        const current = await getGlobalById(id);

        if (!current) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Tipo de pago no encontrado",
          });
        }

        const [result]: any = await db.query(
          `
              DELETE
              FROM tipo_pago

              WHERE id = ?

              LIMIT 1
            `,
          [id]
        );

        reply.header("Cache-Control", "no-store");

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,

            message: "Tipo de pago no encontrado",
          });
        }

        return reply.send({
          ok: true,

          deleted: id,
        });
      } catch (err: any) {
        reply.header("Cache-Control", "no-store");

        if (
          err?.errno === 1451 ||
          err?.code === "ER_ROW_IS_REFERENCED_2" ||
          String(err?.code ?? "").includes("ER_ROW_IS_REFERENCED")
        ) {
          return reply.code(409).send({
            ok: false,

            message:
              "No se puede eliminar el tipo de pago porque está asociado a academias, tarifas, planes o pagos registrados. Puede deshabilitarlo globalmente en su lugar.",
          });
        }

        return handleDatabaseError(reply, err, "eliminar");
      }
    }
  );
}
