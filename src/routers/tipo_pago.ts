// src/routers/tipo_pago.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z, ZodError } from "zod";

import { db } from "../db";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * =========================================================
 * WELI - TIPOS DE PAGO
 * =========================================================
 *
 * tipo_pago
 * ---------------------------------------------------------
 * Catálogo GLOBAL del sistema.
 *
 * Campos reales:
 *
 * - id
 * - nombre
 * - descripcion
 * - estado_id
 *
 * academia_tipo_pago
 * ---------------------------------------------------------
 * Determina qué conceptos están habilitados
 * para una academia.
 *
 * tarifas_academia
 * ---------------------------------------------------------
 * Determina el valor base configurado
 * por academia para cada tipo de pago.
 *
 * Rutas:
 *
 * GET /
 *   Catálogo EFECTIVO de la academia.
 *
 * GET /catalogo
 *   Catálogo GLOBAL.
 *   Solo Superadmin.
 *
 * GET /:id
 *   Tipo de pago habilitado para
 *   la academia efectiva.
 *
 * POST /
 * PUT /:id
 * PATCH /:id
 * DELETE /:id
 *   Administración del catálogo global.
 *   Solo Superadmin.
 *
 * Seguridad:
 *
 * Admin:
 * - puede leer configuración efectiva
 *   de su academia.
 *
 * Superadmin:
 * - puede leer configuración efectiva
 *   de la academia seleccionada.
 * - puede consultar y administrar
 *   catálogo global.
 *
 * academia_id:
 *
 * Admin:
 * - proviene del JWT firmado.
 *
 * Superadmin:
 * - proviene de x-academia-id.
 *
 * academia_id NUNCA se recibe
 * desde el body.
 * =========================================================
 */

/* =========================================================
   SCHEMAS
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const EstadoSchema = z.coerce.number().int().positive().max(255);

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

/* =========================================================
   HELPERS GENERALES
========================================================= */

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

/* =========================================================
   ACADEMIA EFECTIVA
========================================================= */

function resolveAcademiaId(req: FastifyRequest): number {
  const academiaId = Number(getEffectiveAcademiaId(req));

  if (!Number.isInteger(academiaId) || academiaId <= 0) {
    const err: any = new Error("Academia efectiva inválida");

    err.statusCode = 403;

    throw err;
  }

  return academiaId;
}

/* =========================================================
   NORMALIZACIÓN GLOBAL
========================================================= */

function normalizeGlobal(row: any) {
  return {
    id: Number(row.id),

    nombre: String(row.nombre ?? ""),

    descripcion: row.descripcion == null ? null : String(row.descripcion),

    estado_id: Number(row.estado_id),
  };
}

/* =========================================================
   NORMALIZACIÓN ACADEMIA
========================================================= */

function normalizeScoped(row: any) {
  return {
    /*
     * ID global de tipo_pago.
     */
    id: Number(row.id),

    tipo_pago_id: Number(row.id),

    nombre: String(row.nombre ?? ""),

    descripcion: row.descripcion == null ? null : String(row.descripcion),

    /*
     * Estado del catálogo global.
     */
    estado_id: Number(row.estado_id),

    /*
     * Relación con academia.
     */
    academia_tipo_pago_id: Number(row.academia_tipo_pago_id),

    academia_id: Number(row.academia_id),

    academia_estado_id: Number(row.academia_estado_id),

    /*
     * Tarifa base.
     *
     * Puede ser NULL si todavía
     * no existe una tarifa configurada.
     */
    tarifa_id: row.tarifa_id == null ? null : Number(row.tarifa_id),

    monto: row.monto == null ? null : Number(row.monto),

    tarifa_estado_id: row.tarifa_estado_id == null ? null : Number(row.tarifa_estado_id),
  };
}

/* =========================================================
   DUPLICADOS GLOBALES
========================================================= */

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
                ) =
                LOWER(?)

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
              ) =
              LOWER(?)

        LIMIT 1
      `,
    [normalized]
  );

  return Array.isArray(rows) && rows.length > 0;
}

/* =========================================================
   OBTENER GLOBAL
========================================================= */

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

/* =========================================================
   OBTENER TIPO DE PAGO DE ACADEMIA
========================================================= */

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
            AS tarifa_estado_id

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

        WHERE tp.id = ?

        LIMIT 1
      `,
    [academiaId, tipoPagoId]
  );

  return rows?.length ? rows[0] : null;
}

/* =========================================================
   ERRORES
========================================================= */

function handleDatabaseError(reply: FastifyReply, err: any, operation: string) {
  reply.header("Cache-Control", "no-store");

  const status = Number(err?.statusCode ?? 0);

  if (status === 400 || status === 401 || status === 403 || status === 404 || status === 409) {
    return reply.code(status).send({
      ok: false,

      message: err?.message ?? "No fue posible procesar la solicitud",
    });
  }

  /* -------------------------------------------------------
     DUPLICADO
  ------------------------------------------------------- */

  if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
    return reply.code(409).send({
      ok: false,

      message: "Ya existe un tipo de pago con ese nombre",
    });
  }

  /* -------------------------------------------------------
     REGISTRO REFERENCIADO
  ------------------------------------------------------- */

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

  /* -------------------------------------------------------
     ERROR GENERAL
  ------------------------------------------------------- */

  console.error(`[tipo_pago] ${operation}`, err);

  return reply.code(500).send({
    ok: false,

    message: `Error al ${operation} tipo de pago`,

    detail: err?.message,
  });
}

/* =========================================================
   ROUTER
========================================================= */

export default async function tipo_pago(app: FastifyInstance) {
  /*
   * Catálogo efectivo:
   *
   * Admin y Superadmin.
   *
   * Staff no administra
   * configuración financiera.
   */
  const canReadScoped = [requireAuth, requireRoles([1, 3])];

  /*
   * Catálogo GLOBAL:
   *
   * solamente Superadmin.
   */
  const onlySuper = [requireAuth, requireRoles([3])];

  /* =======================================================
     HEALTH
  ======================================================= */

  app.get(
    "/health",
    {
      preHandler: canReadScoped,
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

  /* =======================================================
     GET /catalogo
     CATÁLOGO GLOBAL COMPLETO
     SOLO SUPERADMIN
  ======================================================= */

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
                estado_id ASC,
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

  /* =======================================================
     GET /
     TIPOS DE PAGO HABILITADOS PARA LA ACADEMIA
  ======================================================= */

  app.get(
    "/",
    {
      preHandler: canReadScoped,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const academiaId = resolveAcademiaId(req);

        /*
         * NO consultamos tipo_pago directamente.
         *
         * La tabla conductora es academia_tipo_pago.
         *
         * Si existen 20 tipos globales
         * pero la academia habilitó 3,
         * esta ruta devuelve SOLO 3.
         */
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

  /* =======================================================
     GET /:id
     TIPO DE PAGO DE LA ACADEMIA
  ======================================================= */

  app.get(
    "/:id",
    {
      preHandler: canReadScoped,
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

        /*
         * GET / representa configuración
         * efectiva, por lo tanto tanto
         * catálogo como relación deben
         * estar activos.
         */
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

  /* =======================================================
     POST /
     CREAR TIPO GLOBAL
     SOLO SUPERADMIN
  ======================================================= */

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

  /* =======================================================
     PUT /:id
     REEMPLAZO GLOBAL
     SOLO SUPERADMIN
  ======================================================= */

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

        const nombre = normalizeName(body.nombre);

        const descripcion = normalizeDescription(body.descripcion);

        const estadoId = Number(body.estado_id);

        const current = await getGlobalById(id);

        if (!current) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Tipo de pago no encontrado",
          });
        }

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

  /* =======================================================
     PATCH /:id
     ACTUALIZACIÓN GLOBAL PARCIAL
     SOLO SUPERADMIN
  ======================================================= */

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

  /* =======================================================
     DELETE /:id
     ELIMINACIÓN GLOBAL
     SOLO SUPERADMIN
  ======================================================= */

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

        /*
         * Referencias actuales posibles:
         *
         * - academia_tipo_pago
         * - tarifas_academia
         * - academia_plan_tipo_pago
         * - pago_detalle
         *
         * plan_reglas YA NO depende
         * de tipo_pago.
         */
        if (
          err?.errno === 1451 ||
          err?.code === "ER_ROW_IS_REFERENCED_2" ||
          String(err?.code ?? "").includes("ER_ROW_IS_REFERENCED")
        ) {
          return reply.code(409).send({
            ok: false,

            message:
              "No se puede eliminar el tipo de pago porque está asociado a academias, tarifas, beneficios o pagos registrados",
          });
        }

        return handleDatabaseError(reply, err, "eliminar");
      }
    }
  );
}
