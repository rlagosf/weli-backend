// src/routers/academias.ts

import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";

import { db } from "../db";
import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/* =========================================================
   CONSTANTES
========================================================= */

const MAX_SUCURSALES = 50;
const MAX_TIPOS_PAGO = 50;
const MAX_PLANES = 50;
const MAX_NOMBRE_SUCURSAL = 100;

const ESTADO_ACTIVO = 1;
const ESTADO_INACTIVO = 2;

/* =========================================================
   SCHEMAS BASE
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const EstadoSchema = z.coerce.number().int().positive();

const TipoPagoConfigSchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive(),

    monto: z.coerce.number().finite().nonnegative().max(999999999.99),

    estado_id: EstadoSchema.optional().default(ESTADO_ACTIVO),
  })
  .strict();

/* =========================================================
   CREATE
========================================================= */

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(2).max(120),

    rut_academia: z.coerce.number().int().positive().max(99_999_999),

    deporte_id: z.coerce.number().int().positive(),

    estado_id: EstadoSchema.optional().default(ESTADO_ACTIVO),

    sucursales: z
      .array(z.string().trim().min(2).max(MAX_NOMBRE_SUCURSAL))
      .min(1, "Debe registrar al menos una sucursal")
      .max(MAX_SUCURSALES, `No se pueden registrar más de ${MAX_SUCURSALES} sucursales`),

    /*
     * Cada concepto proviene del catálogo global tipo_pago,
     * pero el monto pertenece exclusivamente a la academia.
     */
    tipos_pago: z
      .array(TipoPagoConfigSchema)
      .min(1, "Debe configurar al menos un tipo de pago")
      .max(MAX_TIPOS_PAGO, `No se pueden configurar más de ${MAX_TIPOS_PAGO} tipos de pago`),

    /*
     * IDs provenientes exclusivamente de planes_catalogo.
     *
     * SIN BENEFICIO será agregado automáticamente aunque
     * el frontend no lo envíe.
     */
    planes: z.array(z.coerce.number().int().positive()).max(MAX_PLANES).optional().default([]),
  })
  .strict();

/* =========================================================
   UPDATE
========================================================= */

const UpdateSucursalSchema = z
  .object({
    id: z.coerce.number().int().positive().optional(),

    nombre: z.string().trim().min(2).max(MAX_NOMBRE_SUCURSAL),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z.string().trim().min(2).max(120).optional(),

    rut_academia: z.coerce.number().int().positive().max(99_999_999).optional(),

    deporte_id: z.coerce.number().int().positive().optional(),

    estado_id: EstadoSchema.optional(),

    sucursales: z.array(UpdateSucursalSchema).min(1).max(MAX_SUCURSALES).optional(),

    tipos_pago: z.array(TipoPagoConfigSchema).min(1).max(MAX_TIPOS_PAGO).optional(),

    planes: z.array(z.coerce.number().int().positive()).max(MAX_PLANES).optional(),
  })
  .strict();

/* =========================================================
   LIST
========================================================= */

const ListQuery = z.object({
  limit: z.coerce.number().int().positive().max(500).default(100),

  offset: z.coerce.number().int().nonnegative().default(0),

  q: z.string().trim().min(1).optional(),

  estado_id: z.coerce.number().int().positive().optional(),

  deporte_id: z.coerce.number().int().positive().optional(),
});

/* =========================================================
   HELPERS GENERALES
========================================================= */

function normalizeName(value: string): string {
  return String(value ?? "")
    .trim()
    .replace(/\s+/g, " ");
}

function comparableName(value: string): string {
  return normalizeName(value).toLocaleLowerCase("es");
}

function badRequest(message: string): never {
  const error: any = new Error(message);
  error.statusCode = 400;
  throw error;
}

function conflict(message: string): never {
  const error: any = new Error(message);
  error.statusCode = 409;
  throw error;
}

function extractRole(req: any): number {
  const raw = req?.user?.rol_id ?? req?.user?.role_id ?? req?.user?.role ?? req?.user?.rol ?? req?.rol_id ?? 0;

  const role = Number(raw);

  return Number.isInteger(role) ? role : 0;
}

function resolveAcademiaId(req: FastifyRequest): number {
  const academiaId = Number(getEffectiveAcademiaId(req));

  if (!Number.isInteger(academiaId) || academiaId <= 0) {
    const error: any = new Error("Academia efectiva inválida");
    error.statusCode = 403;
    throw error;
  }

  return academiaId;
}

function mysqlError(error: any): {
  status: number;
  message: string;
} {
  if (error instanceof z.ZodError) {
    const first = error.issues?.[0];

    return {
      status: 400,
      message: first?.message ?? "Datos inválidos",
    };
  }

  if (error?.code === "ER_DUP_ENTRY") {
    return {
      status: 409,
      message: "Ya existe un registro con los mismos datos",
    };
  }

  if (error?.code === "ER_NO_REFERENCED_ROW_2") {
    return {
      status: 400,
      message: "Uno de los datos relacionados no existe o no es válido",
    };
  }

  if (error?.code === "ER_ROW_IS_REFERENCED_2") {
    return {
      status: 409,
      message: "El registro posee información relacionada y no puede eliminarse",
    };
  }

  return {
    status: Number(error?.statusCode ?? 400) || 400,
    message: error?.message ?? "BAD_REQUEST",
  };
}

function assertUniqueNames(values: string[], label: string): void {
  const normalized = values.map(comparableName);

  if (new Set(normalized).size !== normalized.length) {
    badRequest(`No se pueden registrar ${label} duplicados`);
  }
}

function assertUniquePositiveIds(values: number[], label: string): void {
  const ids = values.map(Number);

  if (ids.some((id) => !Number.isInteger(id) || id <= 0)) {
    badRequest(`Hay ${label} inválidos`);
  }

  if (new Set(ids).size !== ids.length) {
    badRequest(`No se pueden registrar ${label} duplicados`);
  }
}

function assertUniqueTiposPago(items: Array<{ tipo_pago_id: number }>): void {
  assertUniquePositiveIds(
    items.map((item) => Number(item.tipo_pago_id)),
    "tipos de pago"
  );
}

/* =========================================================
   CATÁLOGO TIPO_PAGO
========================================================= */

async function validateTiposPagoCatalogo(conn: any, ids: number[]): Promise<void> {
  const uniqueIds = [...new Set(ids.map(Number))];

  if (!uniqueIds.length) {
    return;
  }

  const placeholders = uniqueIds.map(() => "?").join(", ");

  const [rows]: any = await conn.query(
    `
      SELECT id
      FROM tipo_pago
      WHERE id IN (${placeholders})
        AND estado_id = ?
    `,
    [...uniqueIds, ESTADO_ACTIVO]
  );

  const validIds = new Set<number>((rows ?? []).map((row: any) => Number(row.id)));

  for (const id of uniqueIds) {
    if (!validIds.has(id)) {
      badRequest(`El tipo de pago ${id} no existe o no está activo en el catálogo global`);
    }
  }
}

/* =========================================================
   CATÁLOGO PLANES
========================================================= */

async function getSinBeneficioPlanId(conn: any): Promise<number> {
  const [rows]: any = await conn.query(
    `
      SELECT id
      FROM planes_catalogo
      WHERE UPPER(TRIM(nombre)) = 'SIN BENEFICIO'
        AND estado_id = ?
      LIMIT 1
    `,
    [ESTADO_ACTIVO]
  );

  const id = Number(rows?.[0]?.id);

  if (!Number.isInteger(id) || id <= 0) {
    throw new Error('El catálogo global no contiene un plan activo "SIN BENEFICIO"');
  }

  return id;
}

async function validatePlanesCatalogo(conn: any, ids: number[]): Promise<void> {
  const uniqueIds = [...new Set(ids.map(Number))];

  if (!uniqueIds.length) {
    return;
  }

  const placeholders = uniqueIds.map(() => "?").join(", ");

  const [rows]: any = await conn.query(
    `
      SELECT id
      FROM planes_catalogo
      WHERE id IN (${placeholders})
        AND estado_id = ?
    `,
    [...uniqueIds, ESTADO_ACTIVO]
  );

  const validIds = new Set<number>((rows ?? []).map((row: any) => Number(row.id)));

  for (const id of uniqueIds) {
    if (!validIds.has(id)) {
      badRequest(`El plan ${id} no existe o no está activo en el catálogo global`);
    }
  }
}

async function normalizePlanesAcademia(conn: any, requestedIds: number[]): Promise<number[]> {
  assertUniquePositiveIds(requestedIds, "planes");

  await validatePlanesCatalogo(conn, requestedIds);

  const sinBeneficioId = await getSinBeneficioPlanId(conn);

  return [...new Set([sinBeneficioId, ...requestedIds.map(Number)])];
}

/* =========================================================
   UPSERT CONFIGURACIÓN FINANCIERA
========================================================= */

async function upsertTipoPagoAcademia(
  conn: any,
  academiaId: number,
  tipoPagoId: number,
  estadoId: number
): Promise<void> {
  await conn.query(
    `
      INSERT INTO academia_tipo_pago (
        academia_id,
        tipo_pago_id,
        estado_id
      )
      VALUES (?, ?, ?)

      ON DUPLICATE KEY UPDATE
        estado_id = VALUES(estado_id)
    `,
    [academiaId, tipoPagoId, estadoId]
  );
}

async function upsertTarifaAcademia(
  conn: any,
  academiaId: number,
  tipoPagoId: number,
  monto: number,
  estadoId: number
): Promise<void> {
  await conn.query(
    `
      INSERT INTO tarifas_academia (
        academia_id,
        tipo_pago_id,
        monto,
        estado_id
      )
      VALUES (?, ?, ?, ?)

      ON DUPLICATE KEY UPDATE
        monto = VALUES(monto),
        estado_id = VALUES(estado_id),
        updated_at = CURRENT_TIMESTAMP
    `,
    [academiaId, tipoPagoId, monto, estadoId]
  );
}

async function upsertAcademiaPlan(conn: any, academiaId: number, planId: number, estadoId: number): Promise<void> {
  await conn.query(
    `
      INSERT INTO academia_plan (
        academia_id,
        plan_id,
        estado_id
      )
      VALUES (?, ?, ?)

      ON DUPLICATE KEY UPDATE
        estado_id = VALUES(estado_id),
        updated_at = CURRENT_TIMESTAMP
    `,
    [academiaId, planId, estadoId]
  );
}

/* =========================================================
   ROUTER
========================================================= */

export default async function academias(app: FastifyInstance) {
  const onlySuper = [requireAuth, requireRoles([3])];

  const canReadOwnAcademia = [requireAuth, requireRoles([1, 2, 3])];

  /* =======================================================
     HEALTH
  ======================================================= */

  app.get(
    "/health",
    {
      preHandler: onlySuper,
    },
    async () => ({
      module: "academias",
      status: "ready",
      timestamp: new Date().toISOString(),
    })
  );

  /* =======================================================
     LIST
     GET /api/academias
  ======================================================= */

  app.get(
    "/",
    {
      preHandler: onlySuper,
    },
    async (req, reply) => {
      try {
        const { limit, offset, q, estado_id, deporte_id } = ListQuery.parse((req as any).query);

        const where: string[] = [];
        const params: any[] = [];

        if (q) {
          where.push(`(a.nombre LIKE ? OR CAST(a.rut_academia AS CHAR) LIKE ?)`);

          params.push(`%${q}%`, `%${q.replace(/\D/g, "")}%`);
        }

        if (estado_id !== undefined) {
          where.push("a.estado_id = ?");
          params.push(estado_id);
        }

        if (deporte_id !== undefined) {
          where.push("a.deporte_id = ?");
          params.push(deporte_id);
        }

        const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

        const [rows] = await db.query(
          `
            SELECT
              a.id,
              a.nombre,
              a.rut_academia,
              a.deporte_id,
              d.nombre AS deporte_nombre,
              a.estado_id,
              ea.nombre AS estado_nombre,
              a.created_at,
              a.updated_at
            FROM academias a

            LEFT JOIN deportes d
              ON d.id = a.deporte_id

            LEFT JOIN estado_academia ea
              ON ea.id = a.estado_id

            ${whereSql}

            ORDER BY a.id DESC

            LIMIT ?
            OFFSET ?
          `,
          [...params, limit, offset]
        );

        const [countRows]: any = await db.query(
          `
              SELECT COUNT(*) AS total
              FROM academias a
              ${whereSql}
            `,
          params
        );

        return reply.send({
          ok: true,
          total: Number(countRows?.[0]?.total ?? 0),
          limit,
          offset,
          data: rows,
        });
      } catch (error: any) {
        const parsed = mysqlError(error);

        return reply.code(parsed.status).send({
          ok: false,
          message: parsed.message,
        });
      }
    }
  );

  /* =======================================================
     GET BY ID
     GET /api/academias/:id
  ======================================================= */

  app.get(
    "/:id",
    {
      preHandler: canReadOwnAcademia,
    },
    async (req, reply) => {
      const paramsParsed = IdParam.safeParse((req as any).params);

      if (!paramsParsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      try {
        const requestedId = paramsParsed.data.id;

        const role = extractRole(req);

        let academiaId = requestedId;

        /*
         * Admin y Staff solo pueden consultar
         * la academia de su JWT.
         *
         * Superadmin puede consultar por ID desde
         * el módulo global de academias.
         */
        if (role !== 3) {
          const effectiveAcademiaId = resolveAcademiaId(req);

          if (Number(requestedId) !== Number(effectiveAcademiaId)) {
            return reply.code(403).send({
              ok: false,
              message: "FORBIDDEN_ACADEMIA",
            });
          }

          academiaId = effectiveAcademiaId;
        }

        const [academiaRows]: any = await db.query(
          `
              SELECT
                a.id,
                a.nombre,
                a.rut_academia,
                a.deporte_id,
                d.nombre AS deporte_nombre,
                a.estado_id,
                ea.nombre AS estado_nombre,
                a.created_at,
                a.updated_at
              FROM academias a

              LEFT JOIN deportes d
                ON d.id = a.deporte_id

              LEFT JOIN estado_academia ea
                ON ea.id = a.estado_id

              WHERE a.id = ?

              LIMIT 1
            `,
          [academiaId]
        );

        if (!academiaRows?.length) {
          return reply.code(404).send({
            ok: false,
            message: "Academia no encontrada",
          });
        }

        /* -----------------------------
           SUCURSALES
        ----------------------------- */

        const [sucursales]: any = await db.query(
          `
              SELECT
                id,
                academia_id,
                nombre
              FROM sucursales_real
              WHERE academia_id = ?
              ORDER BY id ASC
            `,
          [academiaId]
        );

        /* -----------------------------
           TIPOS DE PAGO + TARIFAS
        ----------------------------- */

        const [tiposPago]: any = await db.query(
          `
              SELECT
                atp.id AS relacion_id,
                atp.academia_id,

                tp.id AS tipo_pago_id,
                tp.nombre,
                tp.descripcion,

                atp.estado_id,

                ta.id AS tarifa_id,
                ta.monto,
                ta.estado_id AS tarifa_estado_id,
                ta.created_at AS tarifa_created_at,
                ta.updated_at AS tarifa_updated_at

              FROM academia_tipo_pago atp

              INNER JOIN tipo_pago tp
                ON tp.id = atp.tipo_pago_id

              LEFT JOIN tarifas_academia ta
                ON ta.academia_id = atp.academia_id
               AND ta.tipo_pago_id = atp.tipo_pago_id

              WHERE atp.academia_id = ?

              ORDER BY
                tp.nombre ASC,
                tp.id ASC
            `,
          [academiaId]
        );

        /* -----------------------------
           PLANES GLOBALES HABILITADOS
        ----------------------------- */

        const [planesRows]: any = await db.query(
          `
              SELECT
                ap.id AS relacion_id,
                ap.academia_id,

                pc.id AS plan_id,
                pc.nombre,
                pc.descripcion,

                ap.estado_id,

                pc.created_at,
                pc.updated_at

              FROM academia_plan ap

              INNER JOIN planes_catalogo pc
                ON pc.id = ap.plan_id

              WHERE ap.academia_id = ?

              ORDER BY
                pc.nombre ASC,
                pc.id ASC
            `,
          [academiaId]
        );

        /* -----------------------------
           REGLAS DE LOS PLANES
        ----------------------------- */

        const planIds = (planesRows ?? [])
          .map((row: any) => Number(row.plan_id))
          .filter((id: number) => Number.isInteger(id) && id > 0);

        let reglasRows: any[] = [];

        if (planIds.length) {
          const placeholders = planIds.map(() => "?").join(", ");

          const [rows]: any = await db.query(
            `
                SELECT
                  pr.id,
                  pr.plan_id,
                  pr.tipo_pago_id,
                  tp.nombre AS tipo_pago_nombre,
                  pr.tipo_beneficio,
                  pr.valor,
                  pr.estado_id,
                  pr.created_at,
                  pr.updated_at

                FROM plan_reglas pr

                LEFT JOIN tipo_pago tp
                  ON tp.id = pr.tipo_pago_id

                WHERE pr.plan_id IN (${placeholders})

                ORDER BY
                  pr.plan_id ASC,
                  pr.id ASC
              `,
            planIds
          );

          reglasRows = rows ?? [];
        }

        const planes = (planesRows ?? []).map((plan: any) => ({
          ...plan,

          reglas: reglasRows.filter((regla: any) => Number(regla.plan_id) === Number(plan.plan_id)),
        }));

        return reply.send({
          ok: true,

          item: {
            ...academiaRows[0],

            sucursales: sucursales ?? [],

            tipos_pago: tiposPago ?? [],

            planes,
          },
        });
      } catch (error: any) {
        const parsed = mysqlError(error);

        return reply.code(parsed.status).send({
          ok: false,
          message: parsed.message,
        });
      }
    }
  );

  /* =======================================================
     CREATE
     POST /api/academias
  ======================================================= */

  app.post(
    "/",
    {
      preHandler: onlySuper,
    },
    async (req, reply) => {
      const conn = await db.getConnection();

      let transactionStarted = false;

      try {
        const body = CreateSchema.parse(req.body);

        const nombre = normalizeName(body.nombre);

        const sucursales = body.sucursales.map(normalizeName);

        const tiposPago = body.tipos_pago.map((item) => ({
          tipo_pago_id: Number(item.tipo_pago_id),

          monto: Number(item.monto),

          estado_id: Number(item.estado_id ?? ESTADO_ACTIVO),
        }));

        assertUniqueNames(sucursales, "sucursales");

        assertUniqueTiposPago(tiposPago);

        await validateTiposPagoCatalogo(
          conn,
          tiposPago.map((item) => item.tipo_pago_id)
        );

        const planes = await normalizePlanesAcademia(conn, body.planes.map(Number));

        /* -----------------------------
           RUT ÚNICO
        ----------------------------- */

        const [rutRows]: any = await conn.query(
          `
              SELECT id
              FROM academias
              WHERE rut_academia = ?
              LIMIT 1
            `,
          [body.rut_academia]
        );

        if (rutRows?.length) {
          return reply.code(409).send({
            ok: false,
            message: "Ya existe una academia registrada con ese RUT",
          });
        }

        /* -----------------------------
           TRANSACCIÓN
        ----------------------------- */

        await conn.beginTransaction();
        transactionStarted = true;

        /* -----------------------------
           1. ACADEMIA
        ----------------------------- */

        const [resultAcademia]: any = await conn.query(
          `
              INSERT INTO academias (
                nombre,
                rut_academia,
                deporte_id,
                estado_id
              )
              VALUES (?, ?, ?, ?)
            `,
          [nombre, body.rut_academia, body.deporte_id, body.estado_id]
        );

        const academiaId = Number(resultAcademia.insertId);

        if (!Number.isInteger(academiaId) || academiaId <= 0) {
          throw new Error("No fue posible obtener el ID de la academia creada");
        }

        /* -----------------------------
           2. SUCURSALES
        ----------------------------- */

        for (const nombreSucursal of sucursales) {
          await conn.query(
            `
              INSERT INTO sucursales_real (
                academia_id,
                nombre
              )
              VALUES (?, ?)
            `,
            [academiaId, nombreSucursal]
          );
        }

        /* -----------------------------
           3. TIPO_PAGO + TARIFAS
        ----------------------------- */

        for (const config of tiposPago) {
          await upsertTipoPagoAcademia(conn, academiaId, config.tipo_pago_id, config.estado_id);

          await upsertTarifaAcademia(conn, academiaId, config.tipo_pago_id, config.monto, config.estado_id);
        }

        /* -----------------------------
           4. PLANES GLOBALES
        ----------------------------- */

        for (const planId of planes) {
          await upsertAcademiaPlan(conn, academiaId, planId, ESTADO_ACTIVO);
        }

        await conn.commit();
        transactionStarted = false;

        /* -----------------------------
           RESPUESTA COMPLETA
        ----------------------------- */

        const [sucursalesCreadas]: any = await conn.query(
          `
              SELECT
                id,
                academia_id,
                nombre
              FROM sucursales_real
              WHERE academia_id = ?
              ORDER BY id ASC
            `,
          [academiaId]
        );

        const [tiposPagoCreados]: any = await conn.query(
          `
              SELECT
                atp.id AS relacion_id,
                tp.id AS tipo_pago_id,
                tp.nombre,
                tp.descripcion,
                atp.estado_id,
                ta.id AS tarifa_id,
                ta.monto,
                ta.estado_id AS tarifa_estado_id

              FROM academia_tipo_pago atp

              INNER JOIN tipo_pago tp
                ON tp.id = atp.tipo_pago_id

              INNER JOIN tarifas_academia ta
                ON ta.academia_id = atp.academia_id
               AND ta.tipo_pago_id = atp.tipo_pago_id

              WHERE atp.academia_id = ?

              ORDER BY tp.nombre ASC
            `,
          [academiaId]
        );

        const [planesCreados]: any = await conn.query(
          `
              SELECT
                ap.id AS relacion_id,
                pc.id AS plan_id,
                pc.nombre,
                pc.descripcion,
                ap.estado_id

              FROM academia_plan ap

              INNER JOIN planes_catalogo pc
                ON pc.id = ap.plan_id

              WHERE ap.academia_id = ?

              ORDER BY pc.nombre ASC
            `,
          [academiaId]
        );

        return reply.code(201).send({
          ok: true,

          message: "Academia creada correctamente",

          academia: {
            id: academiaId,
            nombre,
            rut_academia: body.rut_academia,
            deporte_id: body.deporte_id,
            estado_id: body.estado_id,

            sucursales: sucursalesCreadas ?? [],

            tipos_pago: tiposPagoCreados ?? [],

            planes: planesCreados ?? [],
          },
        });
      } catch (error: any) {
        if (transactionStarted) {
          try {
            await conn.rollback();
          } catch {}
        }

        const parsed = mysqlError(error);

        return reply.code(parsed.status).send({
          ok: false,
          message: parsed.message,
        });
      } finally {
        conn.release();
      }
    }
  );

  /* =======================================================
     UPDATE
     PUT /api/academias/:id
  ======================================================= */

  app.put(
    "/:id",
    {
      preHandler: onlySuper,
    },
    async (req, reply) => {
      const paramsParsed = IdParam.safeParse((req as any).params);

      if (!paramsParsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      const academiaId = paramsParsed.data.id;

      const conn = await db.getConnection();

      let transactionStarted = false;

      try {
        const body = UpdateSchema.parse(req.body);

        if (
          body.nombre === undefined &&
          body.rut_academia === undefined &&
          body.deporte_id === undefined &&
          body.estado_id === undefined &&
          body.sucursales === undefined &&
          body.tipos_pago === undefined &&
          body.planes === undefined
        ) {
          return reply.code(400).send({
            ok: false,
            message: "No hay campos para actualizar",
          });
        }

        const [academiaRows]: any = await conn.query(
          `
              SELECT id
              FROM academias
              WHERE id = ?
              LIMIT 1
            `,
          [academiaId]
        );

        if (!academiaRows?.length) {
          return reply.code(404).send({
            ok: false,
            message: "Academia no encontrada",
          });
        }

        /* -----------------------------
           VALIDAR RUT
        ----------------------------- */

        if (body.rut_academia !== undefined) {
          const [rutRows]: any = await conn.query(
            `
                SELECT id
                FROM academias
                WHERE rut_academia = ?
                  AND id <> ?
                LIMIT 1
              `,
            [body.rut_academia, academiaId]
          );

          if (rutRows?.length) {
            return reply.code(409).send({
              ok: false,
              message: "Ya existe otra academia registrada con ese RUT",
            });
          }
        }

        /* -----------------------------
           VALIDAR SUCURSALES
        ----------------------------- */

        if (body.sucursales) {
          assertUniqueNames(
            body.sucursales.map((item) => normalizeName(item.nombre)),
            "sucursales"
          );
        }

        /* -----------------------------
           VALIDAR TIPOS + TARIFAS
        ----------------------------- */

        let tiposPago:
          | Array<{
              tipo_pago_id: number;
              monto: number;
              estado_id: number;
            }>
          | undefined;

        if (body.tipos_pago) {
          tiposPago = body.tipos_pago.map((item) => ({
            tipo_pago_id: Number(item.tipo_pago_id),

            monto: Number(item.monto),

            estado_id: Number(item.estado_id ?? ESTADO_ACTIVO),
          }));

          assertUniqueTiposPago(tiposPago);

          await validateTiposPagoCatalogo(
            conn,
            tiposPago.map((item) => item.tipo_pago_id)
          );
        }

        /* -----------------------------
           VALIDAR PLANES
        ----------------------------- */

        let desiredPlanIds: number[] | undefined;

        if (body.planes) {
          desiredPlanIds = await normalizePlanesAcademia(conn, body.planes.map(Number));
        }

        /* -----------------------------
           TRANSACCIÓN
        ----------------------------- */

        await conn.beginTransaction();
        transactionStarted = true;

        /* =================================================
           1. DATOS PRINCIPALES
        ================================================= */

        const sets: string[] = [];
        const updateParams: any[] = [];

        if (body.nombre !== undefined) {
          sets.push("nombre = ?");

          updateParams.push(normalizeName(body.nombre));
        }

        if (body.rut_academia !== undefined) {
          sets.push("rut_academia = ?");

          updateParams.push(body.rut_academia);
        }

        if (body.deporte_id !== undefined) {
          sets.push("deporte_id = ?");

          updateParams.push(body.deporte_id);
        }

        if (body.estado_id !== undefined) {
          sets.push("estado_id = ?");

          updateParams.push(body.estado_id);
        }

        if (sets.length) {
          updateParams.push(academiaId);

          await conn.query(
            `
              UPDATE academias
              SET ${sets.join(", ")}
              WHERE id = ?
            `,
            updateParams
          );
        }

        /* =================================================
           2. SUCURSALES
        ================================================= */

        if (body.sucursales) {
          const [existingRows]: any = await conn.query(
            `
                SELECT
                  id,
                  nombre
                FROM sucursales_real
                WHERE academia_id = ?
                ORDER BY id ASC
              `,
            [academiaId]
          );

          const existingIds = new Set<number>((existingRows ?? []).map((row: any) => Number(row.id)));

          const desiredIds = new Set<number>();

          for (const sucursal of body.sucursales) {
            const nombreSucursal = normalizeName(sucursal.nombre);

            if (sucursal.id) {
              const sucursalId = Number(sucursal.id);

              if (!existingIds.has(sucursalId)) {
                badRequest(`La sucursal ${sucursalId} no pertenece a esta academia`);
              }

              await conn.query(
                `
                  UPDATE sucursales_real
                  SET nombre = ?
                  WHERE id = ?
                    AND academia_id = ?
                `,
                [nombreSucursal, sucursalId, academiaId]
              );

              desiredIds.add(sucursalId);
            } else {
              const [result]: any = await conn.query(
                `
                    INSERT INTO sucursales_real (
                      academia_id,
                      nombre
                    )
                    VALUES (?, ?)
                  `,
                [academiaId, nombreSucursal]
              );

              const newId = Number(result.insertId);

              if (!Number.isInteger(newId) || newId <= 0) {
                throw new Error("No fue posible crear la nueva sucursal");
              }

              desiredIds.add(newId);
            }
          }

          /*
           * La lista enviada es autoritativa.
           *
           * Si una sucursal omitida ya tiene jugadores,
           * pagos u otra información relacionada,
           * la FK RESTRICT impedirá eliminarla.
           */
          const removedIds = [...existingIds].filter((id) => !desiredIds.has(id));

          for (const sucursalId of removedIds) {
            await conn.query(
              `
                DELETE FROM sucursales_real
                WHERE academia_id = ?
                  AND id = ?
              `,
              [academiaId, sucursalId]
            );
          }
        }

        /* =================================================
           3. TIPOS DE PAGO + TARIFAS
        ================================================= */

        if (tiposPago) {
          /*
           * No borramos configuraciones históricas.
           *
           * Primero dejamos las existentes inactivas y
           * luego reactivamos/configuramos las recibidas.
           *
           * Esto preserva tarifa_id para pago_detalle.
           */
          await conn.query(
            `
              UPDATE academia_tipo_pago
              SET estado_id = ?
              WHERE academia_id = ?
            `,
            [ESTADO_INACTIVO, academiaId]
          );

          await conn.query(
            `
              UPDATE tarifas_academia
              SET estado_id = ?
              WHERE academia_id = ?
            `,
            [ESTADO_INACTIVO, academiaId]
          );

          for (const config of tiposPago) {
            await upsertTipoPagoAcademia(conn, academiaId, config.tipo_pago_id, config.estado_id);

            await upsertTarifaAcademia(conn, academiaId, config.tipo_pago_id, config.monto, config.estado_id);
          }
        }

        /* =================================================
           4. PLANES
        ================================================= */

        if (desiredPlanIds) {
          /*
           * Igual que con las tarifas:
           * no eliminamos relaciones históricas.
           */
          await conn.query(
            `
              UPDATE academia_plan
              SET estado_id = ?
              WHERE academia_id = ?
            `,
            [ESTADO_INACTIVO, academiaId]
          );

          for (const planId of desiredPlanIds) {
            await upsertAcademiaPlan(conn, academiaId, planId, ESTADO_ACTIVO);
          }
        }

        await conn.commit();
        transactionStarted = false;

        return reply.send({
          ok: true,
          updated: academiaId,
          message: "Academia actualizada correctamente",
        });
      } catch (error: any) {
        if (transactionStarted) {
          try {
            await conn.rollback();
          } catch {}
        }

        const parsed = mysqlError(error);

        return reply.code(parsed.status).send({
          ok: false,
          message: parsed.message,
        });
      } finally {
        conn.release();
      }
    }
  );

  /* =======================================================
     DELETE
     DELETE /api/academias/:id
  ======================================================= */

  app.delete(
    "/:id",
    {
      preHandler: onlySuper,
    },
    async (req, reply) => {
      const paramsParsed = IdParam.safeParse((req as any).params);

      if (!paramsParsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      const academiaId = paramsParsed.data.id;

      const conn = await db.getConnection();

      let transactionStarted = false;

      try {
        const [academiaRows]: any = await conn.query(
          `
              SELECT id
              FROM academias
              WHERE id = ?
              LIMIT 1
            `,
          [academiaId]
        );

        if (!academiaRows?.length) {
          return reply.code(404).send({
            ok: false,
            message: "Academia no encontrada",
          });
        }

        await conn.beginTransaction();
        transactionStarted = true;

        /*
         * Se eliminan solamente configuraciones propias
         * de la academia.
         *
         * JAMÁS se elimina:
         * - tipo_pago
         * - planes_catalogo
         * - plan_reglas
         */

        await conn.query(
          `
            DELETE FROM academia_plan
            WHERE academia_id = ?
          `,
          [academiaId]
        );

        /*
         * tarifas_academia podría estar referenciada
         * desde pago_detalle.tarifa_id.
         *
         * Si existen pagos históricos, la FK RESTRICT
         * impedirá la eliminación y devolveremos 409.
         */
        await conn.query(
          `
            DELETE FROM tarifas_academia
            WHERE academia_id = ?
          `,
          [academiaId]
        );

        await conn.query(
          `
            DELETE FROM academia_tipo_pago
            WHERE academia_id = ?
          `,
          [academiaId]
        );

        /*
         * Si las sucursales ya poseen jugadores,
         * pagos u otra información relacionada,
         * tampoco serán eliminables.
         */
        await conn.query(
          `
            DELETE FROM sucursales_real
            WHERE academia_id = ?
          `,
          [academiaId]
        );

        const [result]: any = await conn.query(
          `
              DELETE FROM academias
              WHERE id = ?
            `,
          [academiaId]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          throw new Error("Academia no encontrada");
        }

        await conn.commit();
        transactionStarted = false;

        return reply.send({
          ok: true,
          deleted: academiaId,
          message: "Academia eliminada correctamente",
        });
      } catch (error: any) {
        if (transactionStarted) {
          try {
            await conn.rollback();
          } catch {}
        }

        if (error?.code === "ER_ROW_IS_REFERENCED_2") {
          return reply.code(409).send({
            ok: false,
            message:
              "La academia posee información operacional o histórica asociada y no puede eliminarse definitivamente. Desactívala si necesitas conservar sus registros.",
          });
        }

        const parsed = mysqlError(error);

        return reply.code(parsed.status).send({
          ok: false,
          message: parsed.message,
        });
      } finally {
        conn.release();
      }
    }
  );
}
