// src/routers/academias.ts

import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/* =========================================================
   CONSTANTES
========================================================= */

const MAX_SUCURSALES = 50;
const MAX_TIPOS_PAGO = 50;
const MAX_PLANES = 20;
const MAX_TARIFAS_PLAN = 20;
const MAX_NOMBRE_SUCURSAL = 100;

/*
 * TRANSICIÓN:
 * periodicidad dejó de formar parte del contrato comercial.
 * Se conserva internamente mientras planes_academia siga
 * requiriendo un valor NOT NULL.
 */
const LEGACY_PERIODICIDAD = "MENSUAL";

/* =========================================================
   SCHEMAS BASE
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const EstadoSchema = z.coerce.number().int().positive();

const SucursalRelationSchema = z.union([
  z.number().int().positive(),
  z.string().trim().min(2).max(MAX_NOMBRE_SUCURSAL),
]);

const TipoPagoIdSchema = z.coerce.number().int().positive();

/* =========================================================
   TARIFAS
========================================================= */

const CreateTarifaSchema = z
  .object({
    tipo_pago_id: TipoPagoIdSchema,
    monto: z.coerce.number().finite().nonnegative().max(999999999.99),
    sucursales: z
      .array(z.string().trim().min(2).max(MAX_NOMBRE_SUCURSAL))
      .min(1, "Cada tarifa debe aplicar al menos en una sucursal")
      .max(MAX_SUCURSALES),
  })
  .strict();

const UpdateTarifaSchema = z
  .object({
    id: z.coerce.number().int().positive().optional(),
    tipo_pago_id: TipoPagoIdSchema,
    monto: z.coerce.number().finite().nonnegative().max(999999999.99),
    estado_id: EstadoSchema.optional(),
    sucursales: z
      .array(SucursalRelationSchema)
      .min(1, "Cada tarifa debe aplicar al menos en una sucursal")
      .max(MAX_SUCURSALES),
  })
  .strict();

/* =========================================================
   CREATE
========================================================= */

const CreatePlanSchema = z
  .object({
    nombre: z.string().trim().min(2).max(120),
    descripcion: z.string().trim().max(500).nullable().optional(),
    estado_id: EstadoSchema.default(1),
    sucursales: z
      .array(z.string().trim().min(2).max(MAX_NOMBRE_SUCURSAL))
      .min(1, "Cada plan debe estar disponible al menos en una sucursal")
      .max(MAX_SUCURSALES),
    tarifas: z.array(CreateTarifaSchema).min(1, "Cada plan debe registrar al menos una tarifa").max(MAX_TARIFAS_PLAN),
  })
  .strict();

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(2).max(120),
    rut_academia: z.coerce.number().int().positive().max(99_999_999),
    deporte_id: z.coerce.number().int().positive(),
    estado_id: EstadoSchema.optional(),
    sucursales: z
      .array(z.string().trim().min(2).max(MAX_NOMBRE_SUCURSAL))
      .min(1, "Debe registrar al menos una sucursal")
      .max(MAX_SUCURSALES, `No se pueden registrar más de ${MAX_SUCURSALES} sucursales`),
    tipos_pago: z
      .array(TipoPagoIdSchema)
      .min(1, "Debe seleccionar al menos un tipo de pago")
      .max(MAX_TIPOS_PAGO, `No se pueden seleccionar más de ${MAX_TIPOS_PAGO} tipos de pago`),
    planes: z.array(CreatePlanSchema).min(1, "Debe registrar al menos un plan").max(MAX_PLANES),
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

const UpdatePlanSchema = z
  .object({
    id: z.coerce.number().int().positive().optional(),
    nombre: z.string().trim().min(2).max(120),
    descripcion: z.string().trim().max(500).nullable().optional(),
    estado_id: EstadoSchema.default(1),
    sucursales: z
      .array(SucursalRelationSchema)
      .min(1, "Cada plan debe estar disponible al menos en una sucursal")
      .max(MAX_SUCURSALES),
    tarifas: z.array(UpdateTarifaSchema).min(1, "Cada plan debe tener al menos una tarifa").max(MAX_TARIFAS_PLAN),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z.string().trim().min(2).max(120).optional(),
    rut_academia: z.coerce.number().int().positive().max(99_999_999).optional(),
    deporte_id: z.coerce.number().int().positive().optional(),
    estado_id: EstadoSchema.optional(),
    sucursales: z.array(UpdateSucursalSchema).min(1).max(MAX_SUCURSALES).optional(),
    tipos_pago: z.array(TipoPagoIdSchema).min(1).max(MAX_TIPOS_PAGO).optional(),
    planes: z.array(UpdatePlanSchema).max(MAX_PLANES).optional(),
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
   HELPERS
========================================================= */

function normalizeName(value: string): string {
  return String(value ?? "")
    .trim()
    .replace(/\s+/g, " ");
}

function comparableName(value: string): string {
  return normalizeName(value).toLocaleLowerCase("es");
}

function todayMysqlDate(): string {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function extractRole(req: any): number {
  const raw = req?.user?.rol_id ?? req?.user?.role_id ?? req?.user?.role ?? req?.user?.rol ?? req?.rol_id ?? 0;
  const rol = Number(raw);
  return Number.isInteger(rol) ? rol : 0;
}

function mysqlError(error: any): { status: number; message: string } {
  if (error?.code === "ER_DUP_ENTRY") {
    return { status: 409, message: "Ya existe un registro con los mismos datos" };
  }

  if (error?.code === "ER_NO_REFERENCED_ROW_2") {
    return { status: 400, message: "Uno de los datos relacionados no existe o no es válido" };
  }

  if (error?.code === "ER_ROW_IS_REFERENCED_2") {
    return { status: 409, message: "El registro no puede eliminarse porque posee información relacionada" };
  }

  return {
    status: Number(error?.statusCode ?? 400) || 400,
    message: error?.message ?? "BAD_REQUEST",
  };
}

function badRequest(message: string): never {
  const error: any = new Error(message);
  error.statusCode = 400;
  throw error;
}

function assertUniqueNames(values: string[], label: string): void {
  const normalized = values.map(comparableName);
  if (new Set(normalized).size !== normalized.length) {
    badRequest(`No se pueden registrar ${label} duplicados`);
  }
}

function assertUniquePositiveIds(values: number[], label: string): void {
  const normalized = values.map(Number);

  if (normalized.some((id) => !Number.isInteger(id) || id <= 0)) {
    badRequest(`Hay ${label} inválidos`);
  }

  if (new Set(normalized).size !== normalized.length) {
    badRequest(`No se pueden registrar ${label} duplicados`);
  }
}

/* =========================================================
   TIPO_PAGO / ACADEMIA_TIPO_PAGO HELPERS
========================================================= */

async function validateTiposPagoCatalogo(conn: any, ids: number[]): Promise<void> {
  const uniqueIds = [...new Set(ids.map(Number).filter((id) => Number.isInteger(id) && id > 0))];

  if (!uniqueIds.length) return;

  const placeholders = uniqueIds.map(() => "?").join(", ");

  const [rows]: any = await conn.query(
    `SELECT id
     FROM tipo_pago
     WHERE id IN (${placeholders})`,
    uniqueIds
  );

  const valid = new Set<number>((rows ?? []).map((row: any) => Number(row.id)));

  const invalid = uniqueIds.find((id) => !valid.has(id));

  if (invalid !== undefined) {
    badRequest(`El tipo de pago ${invalid} no existe en el catálogo global`);
  }
}

async function getAcademiaTipoPagoIds(conn: any, academiaId: number): Promise<number[]> {
  const [rows]: any = await conn.query(
    `SELECT tipo_pago_id
     FROM academia_tipo_pago
     WHERE academia_id = ?
     ORDER BY tipo_pago_id ASC`,
    [academiaId]
  );

  return (rows ?? [])
    .map((row: any) => Number(row.tipo_pago_id))
    .filter((id: number) => Number.isInteger(id) && id > 0);
}

async function insertAcademiaTiposPago(conn: any, academiaId: number, ids: number[]): Promise<void> {
  if (!ids.length) return;

  await conn.query(
    `INSERT INTO academia_tipo_pago (
       academia_id,
       tipo_pago_id,
       estado_id
     )
     VALUES ?`,
    [ids.map((tipoPagoId) => [academiaId, tipoPagoId, 1])]
  );
}

function assertTarifasUseAllowedTiposPago(
  planes: Array<{
    nombre: string;
    tarifas: Array<{
      tipo_pago_id: number;
    }>;
  }>,
  allowedIds: Set<number>
): void {
  for (const plan of planes) {
    for (const tarifa of plan.tarifas) {
      const tipoPagoId = Number(tarifa.tipo_pago_id);

      if (!allowedIds.has(tipoPagoId)) {
        badRequest(`El tipo de pago ${tipoPagoId} no está habilitado para la academia en el plan "${plan.nombre}"`);
      }
    }
  }
}

/* =========================================================
   SUCURSALES HELPERS
========================================================= */

function buildSucursalMaps(rows: any[]) {
  const byId = new Map<number, any>();
  const byName = new Map<string, any>();

  for (const row of rows ?? []) {
    const id = Number(row.id);

    if (Number.isInteger(id) && id > 0) {
      byId.set(id, row);
      byName.set(comparableName(row.nombre), row);
    }
  }

  return {
    byId,
    byName,
  };
}

function resolveSucursalIds(refs: Array<number | string>, sucursales: any[]): number[] {
  const { byId, byName } = buildSucursalMaps(sucursales);
  const ids: number[] = [];

  for (const ref of refs) {
    const row = typeof ref === "number" ? byId.get(ref) : byName.get(comparableName(ref));

    if (!row) {
      badRequest(`Sucursal inválida o no perteneciente a la academia: ${String(ref)}`);
    }

    const id = Number(row.id);

    if (!ids.includes(id)) {
      ids.push(id);
    }
  }

  return ids;
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

        const [countRows] = await db.query(
          `
            SELECT COUNT(*) AS total
            FROM academias a
            ${whereSql}
          `,
          params
        );

        const total = Array.isArray(countRows) ? ((countRows as any)[0]?.total ?? 0) : 0;

        return reply.send({
          ok: true,
          total,
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
      const parsed = IdParam.safeParse((req as any).params);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      const { id } = parsed.data;

      try {
        const rol = extractRole(req);

        let academiaId = id;

        if (rol !== 3) {
          const effective = getEffectiveAcademiaId(req);

          if (Number(id) !== Number(effective)) {
            return reply.code(403).send({
              ok: false,
              message: "FORBIDDEN_ACADEMIA",
            });
          }

          academiaId = Number(effective);
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

        const [tiposPago]: any = await db.query(
          `
            SELECT
              atp.id AS relacion_id,
              atp.academia_id,
              atp.tipo_pago_id AS id,
              tp.nombre,
              tp.descripcion,
              atp.estado_id
            FROM academia_tipo_pago atp
            INNER JOIN tipo_pago tp
              ON tp.id = atp.tipo_pago_id
            WHERE atp.academia_id = ?
            ORDER BY
              tp.nombre ASC,
              tp.id ASC
          `,
          [academiaId]
        );

        const [planesRows]: any = await db.query(
          `
            SELECT
              p.id,
              p.academia_id,
              p.nombre,
              p.descripcion,
              p.estado_id,
              p.created_at,
              p.updated_at
            FROM planes_academia p
            WHERE p.academia_id = ?
            ORDER BY p.id ASC
          `,
          [academiaId]
        );

        const [planSucursalRows]: any = await db.query(
          `
            SELECT
              ps.plan_id,
              ps.sucursal_id
            FROM plan_sucursal ps
            WHERE ps.academia_id = ?
            ORDER BY
              ps.plan_id,
              ps.sucursal_id
          `,
          [academiaId]
        );

        const [tarifaRows]: any = await db.query(
          `
            SELECT
              pt.id,
              pt.academia_id,
              pt.plan_id,
              pt.tipo_pago_id,
              tp.nombre AS tipo_pago_nombre,
              tp.descripcion AS tipo_pago_descripcion,
              pt.nombre,
              pt.monto,
              pt.vigencia_desde,
              pt.vigencia_hasta,
              pt.estado_id
            FROM plan_tarifas pt
            INNER JOIN tipo_pago tp
              ON tp.id = pt.tipo_pago_id
            INNER JOIN academia_tipo_pago atp
              ON atp.academia_id = pt.academia_id
             AND atp.tipo_pago_id = pt.tipo_pago_id
            WHERE pt.academia_id = ?
            ORDER BY
              pt.plan_id,
              pt.id
          `,
          [academiaId]
        );

        const [tarifaSucursalRows]: any = await db.query(
          `
            SELECT
              ts.tarifa_id,
              ts.sucursal_id
            FROM tarifa_sucursal ts
            WHERE ts.academia_id = ?
            ORDER BY
              ts.tarifa_id,
              ts.sucursal_id
          `,
          [academiaId]
        );

        const planes = (planesRows ?? []).map((plan: any) => {
          const planId = Number(plan.id);

          const sucursalesPlan = (planSucursalRows ?? [])
            .filter((row: any) => Number(row.plan_id) === planId)
            .map((row: any) => Number(row.sucursal_id));

          const tarifas = (tarifaRows ?? [])
            .filter((tarifa: any) => Number(tarifa.plan_id) === planId)
            .map((tarifa: any) => ({
              ...tarifa,
              sucursales: (tarifaSucursalRows ?? [])
                .filter((row: any) => Number(row.tarifa_id) === Number(tarifa.id))
                .map((row: any) => Number(row.sucursal_id)),
            }));

          return {
            ...plan,
            sucursales: sucursalesPlan,
            tarifas,
          };
        });

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
        const parsedError = mysqlError(error);

        return reply.code(parsedError.status).send({
          ok: false,
          message: parsedError.message,
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
        const rut_academia = body.rut_academia;
        const deporte_id = body.deporte_id;
        const estado_id = body.estado_id ?? 1;

        const sucursales = body.sucursales.map(normalizeName);
        const tiposPagoIds = body.tipos_pago.map(Number);

        const planes = body.planes.map((plan) => ({
          nombre: normalizeName(plan.nombre),

          descripcion: plan.descripcion ? normalizeName(plan.descripcion) : null,

          estado_id: plan.estado_id,

          sucursales: plan.sucursales.map(normalizeName),

          tarifas: plan.tarifas.map((tarifa) => ({
            tipo_pago_id: Number(tarifa.tipo_pago_id),
            monto: Number(tarifa.monto),
            sucursales: tarifa.sucursales.map(normalizeName),
          })),
        }));

        assertUniqueNames(sucursales, "sucursales");

        assertUniquePositiveIds(tiposPagoIds, "tipos de pago");

        assertUniqueNames(
          planes.map((plan) => plan.nombre),
          "planes"
        );

        const sucursalesValidas = new Set(sucursales.map(comparableName));

        for (const plan of planes) {
          assertUniqueNames(plan.sucursales, `sucursales dentro del plan "${plan.nombre}"`);

          const planSucursales = new Set(plan.sucursales.map(comparableName));

          for (const sucursal of plan.sucursales) {
            if (!sucursalesValidas.has(comparableName(sucursal))) {
              badRequest(`La sucursal "${sucursal}" no pertenece a la academia que se está creando`);
            }
          }

          for (const tarifa of plan.tarifas) {
            assertUniqueNames(tarifa.sucursales, `sucursales dentro de una tarifa del plan "${plan.nombre}"`);

            for (const sucursal of tarifa.sucursales) {
              const comparable = comparableName(sucursal);

              if (!sucursalesValidas.has(comparable)) {
                badRequest(`La sucursal "${sucursal}" no pertenece a la academia`);
              }

              if (!planSucursales.has(comparable)) {
                badRequest(
                  `La tarifa del plan "${plan.nombre}" no puede aplicarse en "${sucursal}" porque el plan no está disponible en esa sucursal`
                );
              }
            }
          }
        }

        await validateTiposPagoCatalogo(conn, tiposPagoIds);

        const allowedTipoPagoIds = new Set(tiposPagoIds);

        assertTarifasUseAllowedTiposPago(planes, allowedTipoPagoIds);

        const [rutRows]: any = await conn.query(
          `
            SELECT id
            FROM academias
            WHERE rut_academia = ?
            LIMIT 1
          `,
          [rut_academia]
        );

        if (rutRows?.length) {
          return reply.code(409).send({
            ok: false,
            message: "Ya existe una academia registrada con ese RUT",
          });
        }

        await conn.beginTransaction();

        transactionStarted = true;

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
          [nombre, rut_academia, deporte_id, estado_id]
        );

        const academiaId = Number(resultAcademia.insertId);

        if (!Number.isInteger(academiaId) || academiaId <= 0) {
          throw new Error("No fue posible obtener el ID de la academia creada");
        }

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

        if ((sucursalesCreadas ?? []).length !== sucursales.length) {
          throw new Error("No fue posible confirmar todas las sucursales creadas");
        }

        const { byName: sucursalByName } = buildSucursalMaps(sucursalesCreadas);

        await insertAcademiaTiposPago(conn, academiaId, tiposPagoIds);

        const [tiposPagoAsociados]: any = await conn.query(
          `
            SELECT
              atp.id AS relacion_id,
              atp.academia_id,
              atp.tipo_pago_id AS id,
              tp.nombre,
              tp.descripcion,
              atp.estado_id
            FROM academia_tipo_pago atp
            INNER JOIN tipo_pago tp
              ON tp.id = atp.tipo_pago_id
            WHERE atp.academia_id = ?
            ORDER BY
              tp.nombre ASC,
              tp.id ASC
          `,
          [academiaId]
        );

        const planesCreados: any[] = [];

        const vigenciaDesde = todayMysqlDate();

        for (const plan of planes) {
          const [resultPlan]: any = await conn.query(
            `
              INSERT INTO planes_academia (
                academia_id,
                nombre,
                descripcion,
                periodicidad,
                estado_id
              )
              VALUES (?, ?, ?, ?, ?)
            `,
            [academiaId, plan.nombre, plan.descripcion, LEGACY_PERIODICIDAD, plan.estado_id]
          );

          const planId = Number(resultPlan.insertId);

          if (!Number.isInteger(planId) || planId <= 0) {
            throw new Error("No fue posible obtener el ID del plan creado");
          }

          const planSucursalIds = plan.sucursales.map((nombreSucursal) => {
            const row = sucursalByName.get(comparableName(nombreSucursal));

            if (!row) {
              throw new Error(`Sucursal no encontrada: ${nombreSucursal}`);
            }

            return Number(row.id);
          });

          if (planSucursalIds.length) {
            await conn.query(
              `
                INSERT INTO plan_sucursal (
                  academia_id,
                  plan_id,
                  sucursal_id
                )
                VALUES ?
              `,
              [planSucursalIds.map((sucursalId) => [academiaId, planId, sucursalId])]
            );
          }

          const tarifasCreadas: any[] = [];

          for (const tarifa of plan.tarifas) {
            const tipoPagoId = Number(tarifa.tipo_pago_id);

            if (!allowedTipoPagoIds.has(tipoPagoId)) {
              badRequest(`El tipo de pago ${tipoPagoId} no está habilitado para esta academia`);
            }

            const [resultTarifa]: any = await conn.query(
              `
                INSERT INTO plan_tarifas (
                  academia_id,
                  plan_id,
                  tipo_pago_id,
                  nombre,
                  monto,
                  vigencia_desde,
                  vigencia_hasta,
                  estado_id
                )
                VALUES (?, ?, ?, ?, ?, ?, NULL, ?)
              `,
              [academiaId, planId, tipoPagoId, plan.nombre, tarifa.monto, vigenciaDesde, plan.estado_id]
            );

            const tarifaId = Number(resultTarifa.insertId);

            if (!Number.isInteger(tarifaId) || tarifaId <= 0) {
              throw new Error("No fue posible obtener el ID de la tarifa creada");
            }

            const tarifaSucursalIds = tarifa.sucursales.map((nombreSucursal) => {
              const row = sucursalByName.get(comparableName(nombreSucursal));

              if (!row) {
                throw new Error(`Sucursal no encontrada: ${nombreSucursal}`);
              }

              return Number(row.id);
            });

            if (tarifaSucursalIds.length) {
              await conn.query(
                `
                  INSERT INTO tarifa_sucursal (
                    academia_id,
                    tarifa_id,
                    sucursal_id
                  )
                  VALUES ?
                `,
                [tarifaSucursalIds.map((sucursalId) => [academiaId, tarifaId, sucursalId])]
              );
            }

            tarifasCreadas.push({
              id: tarifaId,
              academia_id: academiaId,
              plan_id: planId,
              tipo_pago_id: tipoPagoId,
              nombre: plan.nombre,
              monto: tarifa.monto,
              vigencia_desde: vigenciaDesde,
              vigencia_hasta: null,
              estado_id: plan.estado_id,
              sucursales: tarifaSucursalIds,
            });
          }

          planesCreados.push({
            id: planId,
            academia_id: academiaId,
            nombre: plan.nombre,
            descripcion: plan.descripcion,
            estado_id: plan.estado_id,
            sucursales: planSucursalIds,
            tarifas: tarifasCreadas,
          });
        }

        await conn.commit();

        transactionStarted = false;

        return reply.code(201).send({
          ok: true,
          message: "Academia creada correctamente",
          academia: {
            id: academiaId,
            nombre,
            rut_academia,
            deporte_id,
            estado_id,
            sucursales: sucursalesCreadas,
            tipos_pago: tiposPagoAsociados ?? [],
            planes: planesCreados,
          },
        });
      } catch (error: any) {
        if (transactionStarted) {
          try {
            await conn.rollback();
          } catch {}
        }

        const parsedError = mysqlError(error);

        return reply.code(parsedError.status).send({
          ok: false,
          message: parsedError.message,
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
      const parsed = IdParam.safeParse((req as any).params);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      const { id: academiaId } = parsed.data;

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

        if (body.sucursales) {
          assertUniqueNames(
            body.sucursales.map((sucursal) => normalizeName(sucursal.nombre)),
            "sucursales"
          );
        }

        if (body.tipos_pago) {
          assertUniquePositiveIds(body.tipos_pago, "tipos de pago");

          await validateTiposPagoCatalogo(conn, body.tipos_pago);
        }

        if (body.planes) {
          assertUniqueNames(
            body.planes.map((plan) => normalizeName(plan.nombre)),
            "planes"
          );
        }

        const currentTipoPagoIds = await getAcademiaTipoPagoIds(conn, academiaId);

        const desiredTipoPagoIds = body.tipos_pago ? body.tipos_pago.map(Number) : currentTipoPagoIds;

        const allowedTipoPagoIds = new Set(desiredTipoPagoIds);

        if (body.planes) {
          assertTarifasUseAllowedTiposPago(
            body.planes.map((plan) => ({
              nombre: normalizeName(plan.nombre),
              tarifas: plan.tarifas.map((tarifa) => ({
                tipo_pago_id: Number(tarifa.tipo_pago_id),
              })),
            })),
            allowedTipoPagoIds
          );
        }

        await conn.beginTransaction();

        transactionStarted = true;

        /* =================================================
           1. DATOS PRINCIPALES
        ================================================= */

        const sets: string[] = [];
        const params: any[] = [];

        if (body.nombre !== undefined) {
          sets.push("nombre = ?");
          params.push(normalizeName(body.nombre));
        }

        if (body.rut_academia !== undefined) {
          sets.push("rut_academia = ?");
          params.push(body.rut_academia);
        }

        if (body.deporte_id !== undefined) {
          sets.push("deporte_id = ?");
          params.push(body.deporte_id);
        }

        if (body.estado_id !== undefined) {
          sets.push("estado_id = ?");
          params.push(body.estado_id);
        }

        if (sets.length) {
          params.push(academiaId);

          await conn.query(
            `
              UPDATE academias
              SET ${sets.join(", ")}
              WHERE id = ?
            `,
            params
          );
        }

        /* =================================================
           2. SUCURSALES
        ================================================= */

        const [sucursalesAntes]: any = await conn.query(
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

        const existingSucursalIds = new Set<number>((sucursalesAntes ?? []).map((row: any) => Number(row.id)));

        if (body.sucursales) {
          const desiredSucursalIds = new Set<number>();

          for (const sucursal of body.sucursales) {
            const nombreSucursal = normalizeName(sucursal.nombre);

            if (sucursal.id) {
              const sucursalId = Number(sucursal.id);

              if (!existingSucursalIds.has(sucursalId)) {
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

              desiredSucursalIds.add(sucursalId);
            } else {
              const [resultSucursal]: any = await conn.query(
                `
                    INSERT INTO sucursales_real (
                      academia_id,
                      nombre
                    )
                    VALUES (?, ?)
                  `,
                [academiaId, nombreSucursal]
              );

              const newId = Number(resultSucursal.insertId);

              if (!Number.isInteger(newId) || newId <= 0) {
                throw new Error("No fue posible crear la nueva sucursal");
              }

              desiredSucursalIds.add(newId);
            }
          }

          const removedSucursalIds = [...existingSucursalIds].filter((id) => !desiredSucursalIds.has(id));

          for (const sucursalId of removedSucursalIds) {
            await conn.query(
              `
                DELETE FROM tarifa_sucursal
                WHERE academia_id = ?
                  AND sucursal_id = ?
              `,
              [academiaId, sucursalId]
            );

            await conn.query(
              `
                DELETE FROM plan_sucursal
                WHERE academia_id = ?
                  AND sucursal_id = ?
              `,
              [academiaId, sucursalId]
            );

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

        const [sucursalesActuales]: any = await conn.query(
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

        /* =================================================
           3. PLANES + TARIFAS
        ================================================= */

        if (body.planes) {
          const [planesAntes]: any = await conn.query(
            `
                SELECT id
                FROM planes_academia
                WHERE academia_id = ?
              `,
            [academiaId]
          );

          const existingPlanIds = new Set<number>((planesAntes ?? []).map((row: any) => Number(row.id)));

          const desiredPlanIds = new Set<number>();

          for (const plan of body.planes) {
            const nombrePlan = normalizeName(plan.nombre);

            const descripcion = plan.descripcion ? normalizeName(plan.descripcion) : null;

            const planSucursalIds = resolveSucursalIds(plan.sucursales, sucursalesActuales);

            let planId: number;

            if (plan.id) {
              planId = Number(plan.id);

              if (!existingPlanIds.has(planId)) {
                badRequest(`El plan ${planId} no pertenece a esta academia`);
              }

              await conn.query(
                `
                  UPDATE planes_academia
                  SET
                    nombre = ?,
                    descripcion = ?,
                    estado_id = ?
                  WHERE id = ?
                    AND academia_id = ?
                `,
                [nombrePlan, descripcion, plan.estado_id, planId, academiaId]
              );
            } else {
              const [resultPlan]: any = await conn.query(
                `
                    INSERT INTO planes_academia (
                      academia_id,
                      nombre,
                      descripcion,
                      periodicidad,
                      estado_id
                    )
                    VALUES (?, ?, ?, ?, ?)
                  `,
                [academiaId, nombrePlan, descripcion, LEGACY_PERIODICIDAD, plan.estado_id]
              );

              planId = Number(resultPlan.insertId);

              if (!Number.isInteger(planId) || planId <= 0) {
                throw new Error("No fue posible crear el nuevo plan");
              }
            }

            desiredPlanIds.add(planId);

            await conn.query(
              `
                DELETE FROM plan_sucursal
                WHERE academia_id = ?
                  AND plan_id = ?
              `,
              [academiaId, planId]
            );

            if (planSucursalIds.length) {
              await conn.query(
                `
                  INSERT INTO plan_sucursal (
                    academia_id,
                    plan_id,
                    sucursal_id
                  )
                  VALUES ?
                `,
                [planSucursalIds.map((sucursalId) => [academiaId, planId, sucursalId])]
              );
            }

            const [tarifasAntes]: any = await conn.query(
              `
                  SELECT id
                  FROM plan_tarifas
                  WHERE academia_id = ?
                    AND plan_id = ?
                `,
              [academiaId, planId]
            );

            const existingTarifaIds = new Set<number>((tarifasAntes ?? []).map((row: any) => Number(row.id)));

            const desiredTarifaIds = new Set<number>();

            for (const tarifa of plan.tarifas) {
              const tarifaSucursalIds = resolveSucursalIds(tarifa.sucursales, sucursalesActuales);

              for (const sucursalId of tarifaSucursalIds) {
                if (!planSucursalIds.includes(sucursalId)) {
                  badRequest(
                    `Una tarifa del plan "${nombrePlan}" está vinculada a una sucursal donde el plan no está disponible`
                  );
                }
              }

              const tipoPagoId = Number(tarifa.tipo_pago_id);

              if (!allowedTipoPagoIds.has(tipoPagoId)) {
                badRequest(`El tipo de pago ${tipoPagoId} no está habilitado para esta academia`);
              }

              let tarifaId: number;

              if (tarifa.id) {
                tarifaId = Number(tarifa.id);

                if (!existingTarifaIds.has(tarifaId)) {
                  badRequest(`La tarifa ${tarifaId} no pertenece al plan ${planId}`);
                }

                await conn.query(
                  `
                    UPDATE plan_tarifas
                    SET
                      tipo_pago_id = ?,
                      nombre = ?,
                      monto = ?,
                      estado_id = ?
                    WHERE id = ?
                      AND academia_id = ?
                      AND plan_id = ?
                  `,
                  [
                    tipoPagoId,
                    nombrePlan,
                    tarifa.monto,
                    tarifa.estado_id ?? plan.estado_id,
                    tarifaId,
                    academiaId,
                    planId,
                  ]
                );
              } else {
                const [resultTarifa]: any = await conn.query(
                  `
                      INSERT INTO plan_tarifas (
                        academia_id,
                        plan_id,
                        tipo_pago_id,
                        nombre,
                        monto,
                        vigencia_desde,
                        vigencia_hasta,
                        estado_id
                      )
                      VALUES (?, ?, ?, ?, ?, ?, NULL, ?)
                    `,
                  [
                    academiaId,
                    planId,
                    tipoPagoId,
                    nombrePlan,
                    tarifa.monto,
                    todayMysqlDate(),
                    tarifa.estado_id ?? plan.estado_id,
                  ]
                );

                tarifaId = Number(resultTarifa.insertId);

                if (!Number.isInteger(tarifaId) || tarifaId <= 0) {
                  throw new Error("No fue posible crear la nueva tarifa");
                }
              }

              desiredTarifaIds.add(tarifaId);

              await conn.query(
                `
                  DELETE FROM tarifa_sucursal
                  WHERE academia_id = ?
                    AND tarifa_id = ?
                `,
                [academiaId, tarifaId]
              );

              if (tarifaSucursalIds.length) {
                await conn.query(
                  `
                    INSERT INTO tarifa_sucursal (
                      academia_id,
                      tarifa_id,
                      sucursal_id
                    )
                    VALUES ?
                  `,
                  [tarifaSucursalIds.map((sucursalId) => [academiaId, tarifaId, sucursalId])]
                );
              }
            }

            const removedTarifaIds = [...existingTarifaIds].filter((tarifaId) => !desiredTarifaIds.has(tarifaId));

            for (const tarifaId of removedTarifaIds) {
              await conn.query(
                `
                  DELETE FROM tarifa_sucursal
                  WHERE academia_id = ?
                    AND tarifa_id = ?
                `,
                [academiaId, tarifaId]
              );

              await conn.query(
                `
                  DELETE FROM plan_tarifas
                  WHERE academia_id = ?
                    AND plan_id = ?
                    AND id = ?
                `,
                [academiaId, planId, tarifaId]
              );
            }
          }

          const removedPlanIds = [...existingPlanIds].filter((planId) => !desiredPlanIds.has(planId));

          for (const planId of removedPlanIds) {
            const [tarifasPlan]: any = await conn.query(
              `
                  SELECT id
                  FROM plan_tarifas
                  WHERE academia_id = ?
                    AND plan_id = ?
                `,
              [academiaId, planId]
            );

            for (const tarifa of tarifasPlan ?? []) {
              await conn.query(
                `
                  DELETE FROM tarifa_sucursal
                  WHERE academia_id = ?
                    AND tarifa_id = ?
                `,
                [academiaId, Number(tarifa.id)]
              );
            }

            await conn.query(
              `
                DELETE FROM plan_tarifas
                WHERE academia_id = ?
                  AND plan_id = ?
              `,
              [academiaId, planId]
            );

            await conn.query(
              `
                DELETE FROM plan_sucursal
                WHERE academia_id = ?
                  AND plan_id = ?
              `,
              [academiaId, planId]
            );

            await conn.query(
              `
                DELETE FROM planes_academia
                WHERE academia_id = ?
                  AND id = ?
              `,
              [academiaId, planId]
            );
          }
        }

        /* =================================================
           4. ACADEMIA ↔ TIPO_PAGO
        ================================================= */

        if (body.tipos_pago) {
          const [stillUsedRows]: any = await conn.query(
            `
                SELECT DISTINCT
                  tipo_pago_id
                FROM plan_tarifas
                WHERE academia_id = ?
              `,
            [academiaId]
          );

          const stillUsedIds = (stillUsedRows ?? []).map((row: any) => Number(row.tipo_pago_id));

          const invalidUsed = stillUsedIds.find((tipoPagoId: number) => !allowedTipoPagoIds.has(tipoPagoId));

          if (invalidUsed !== undefined) {
            badRequest(
              `No puedes quitar el tipo de pago ${invalidUsed} porque todavía está utilizado por una tarifa de la academia`
            );
          }

          await conn.query(
            `
              DELETE FROM academia_tipo_pago
              WHERE academia_id = ?
            `,
            [academiaId]
          );

          await insertAcademiaTiposPago(conn, academiaId, desiredTipoPagoIds);
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

        const parsedError = mysqlError(error);

        return reply.code(parsedError.status).send({
          ok: false,
          message: parsedError.message,
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
      const parsed = IdParam.safeParse((req as any).params);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      const { id: academiaId } = parsed.data;

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

        await conn.query(
          `
            DELETE FROM tarifa_sucursal
            WHERE academia_id = ?
          `,
          [academiaId]
        );

        await conn.query(
          `
            DELETE FROM plan_tarifas
            WHERE academia_id = ?
          `,
          [academiaId]
        );

        await conn.query(
          `
            DELETE FROM plan_sucursal
            WHERE academia_id = ?
          `,
          [academiaId]
        );

        await conn.query(
          `
            DELETE FROM planes_academia
            WHERE academia_id = ?
          `,
          [academiaId]
        );

        /*
         * Se elimina solamente la relación con el catálogo.
         * Nunca se eliminan filas de tipo_pago.
         */
        await conn.query(
          `
            DELETE FROM academia_tipo_pago
            WHERE academia_id = ?
          `,
          [academiaId]
        );

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
              "La academia contiene información asociada y no puede eliminarse definitivamente todavía. Desactívala o elimina primero sus dependencias.",
          });
        }

        const parsedError = mysqlError(error);

        return reply.code(parsedError.status).send({
          ok: false,
          message: parsedError.message,
        });
      } finally {
        conn.release();
      }
    }
  );
}
