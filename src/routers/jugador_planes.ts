import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { decryptNullable, decryptRut } from "../services/crypto";
import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

const ESTADO_ACTIVO = 1;

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const DateString = z
  .string()
  .trim()
  .regex(/^\d{4}-\d{2}-\d{2}$/, "Fecha inválida. Formato esperado: YYYY-MM-DD");

const EstadoSchema = z.coerce.number().int().positive().max(255);

const CreateSchema = z
  .object({
    jugador_id: z.coerce.number().int().positive(),
    tipo_pago_id: z.coerce.number().int().positive(),
    plan_id: z.coerce.number().int().positive(),
    fecha_inicio: DateString,
    fecha_fin: z.union([DateString, z.null()]).optional().default(null),
    estado_id: EstadoSchema.default(1),
  })
  .strict();

const PutSchema = z
  .object({
    jugador_id: z.coerce.number().int().positive(),
    tipo_pago_id: z.coerce.number().int().positive(),
    plan_id: z.coerce.number().int().positive(),
    fecha_inicio: DateString,
    fecha_fin: z.union([DateString, z.null()]),
    estado_id: EstadoSchema,
  })
  .strict();

const PatchSchema = z
  .object({
    jugador_id: z.coerce.number().int().positive().optional(),
    tipo_pago_id: z.coerce.number().int().positive().optional(),
    plan_id: z.coerce.number().int().positive().optional(),
    fecha_inicio: DateString.optional(),
    fecha_fin: z.union([DateString, z.null()]).optional(),
    estado_id: EstadoSchema.optional(),
  })
  .strict();

const QuerySchema = z
  .object({
    jugador_id: z.coerce.number().int().positive().optional(),
    tipo_pago_id: z.coerce.number().int().positive().optional(),
    plan_id: z.coerce.number().int().positive().optional(),
    estado_id: EstadoSchema.optional(),
    activos: z.enum(["1", "0"]).optional(),
    limit: z.coerce.number().int().min(1).max(500).default(200),
  })
  .strict();

const BulkItemSchema = z
  .object({
    tipo_pago_id: z.coerce.number().int().positive(),
    plan_id: z.coerce.number().int().positive(),
  })
  .strict();

const BulkSchema = z
  .object({
    jugador_id: z.coerce.number().int().positive(),
    fecha_inicio: DateString,
    fecha_fin: z.union([DateString, z.null()]).optional().default(null),
    estado_id: EstadoSchema.default(1),
    items: z.array(BulkItemSchema).min(1, "Debe existir al menos un tipo de pago"),
  })
  .strict();

function zodDetail(err: ZodError): string {
  return err.issues.map((issue) => `${issue.path.join(".") || "field"}: ${issue.message}`).join("; ");
}

function businessError(message: string, statusCode = 400) {
  const error: any = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function roundMoney(value: number): number {
  return Math.round((Number(value) + Number.EPSILON) * 100) / 100;
}

function resolveAcademiaId(req: FastifyRequest): number {
  const academiaId = Number(getEffectiveAcademiaId(req));

  if (!Number.isInteger(academiaId) || academiaId <= 0) {
    throw businessError("Academia efectiva inválida", 403);
  }

  return academiaId;
}

function normalizeSqlDate(value: any): string | null {
  if (value === null || value === undefined) {
    return null;
  }

  if (typeof value === "string") {
    const match = value.match(/^(\d{4}-\d{2}-\d{2})/);

    if (match) {
      return match[1];
    }
  }

  if (value instanceof Date && !Number.isNaN(value.getTime())) {
    return value.toISOString().slice(0, 10);
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString().slice(0, 10);
}

function validateDates(fechaInicio: string, fechaFin: string | null): void {
  const inicio = new Date(`${fechaInicio}T00:00:00Z`);

  if (Number.isNaN(inicio.getTime())) {
    throw businessError("fecha_inicio inválida");
  }

  if (fechaFin !== null) {
    const fin = new Date(`${fechaFin}T00:00:00Z`);

    if (Number.isNaN(fin.getTime())) {
      throw businessError("fecha_fin inválida");
    }

    if (fin < inicio) {
      throw businessError("fecha_fin no puede ser anterior a fecha_inicio");
    }
  }
}

function normalize(row: any) {
  return {
    id: Number(row.id),
    academia_id: Number(row.academia_id),
    jugador_id: Number(row.jugador_id),
    tipo_pago_id: Number(row.tipo_pago_id),
    plan_id: Number(row.plan_id),
    tarifa_id: Number(row.tarifa_id),
    monto_tarifa: roundMoney(Number(row.monto_tarifa)),
    monto_asignado: roundMoney(Number(row.monto_asignado)),
    descuento_inicial: roundMoney(Number(row.monto_tarifa) - Number(row.monto_asignado)),
    fecha_inicio: normalizeSqlDate(row.fecha_inicio),
    fecha_fin: normalizeSqlDate(row.fecha_fin),
    estado_id: Number(row.estado_id),

    jugador_nombre:
      row.jugador_nombre_enc == null ? undefined : (decryptNullable(String(row.jugador_nombre_enc)) ?? undefined),

    jugador_rut: (() => {
      if (row.jugador_rut_enc == null) {
        return undefined;
      }

      const rut = decryptRut(String(row.jugador_rut_enc));

      if (!rut) {
        return undefined;
      }

      const parsed = Number(rut);

      return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
    })(),

    tipo_pago_nombre: row.tipo_pago_nombre == null ? undefined : String(row.tipo_pago_nombre),

    plan_nombre: row.plan_nombre == null ? undefined : String(row.plan_nombre),

    plan_descripcion: row.plan_descripcion == null ? null : String(row.plan_descripcion),

    plan_estado_id: row.plan_estado_id == null ? undefined : Number(row.plan_estado_id),

    created_at: row.created_at ?? null,
    updated_at: row.updated_at ?? null,
  };
}

async function getJugadorPlan(academiaId: number, id: number, executor: any = db) {
  const [rows]: any = await executor.query(
    `
      SELECT
        jpc.id,
        jpc.academia_id,
        jpc.jugador_id,
        jpc.tipo_pago_id,
        jpc.plan_id,
        jpc.tarifa_id,
        jpc.monto_tarifa,
        jpc.monto_asignado,
        jpc.fecha_inicio,
        jpc.fecha_fin,
        jpc.estado_id,
        jpc.created_at,
        jpc.updated_at,

        j.nombre_jugador_enc AS jugador_nombre_enc,
        j.rut_jugador_enc AS jugador_rut_enc,

        tp.nombre AS tipo_pago_nombre,

        pc.nombre AS plan_nombre,
        pc.descripcion AS plan_descripcion,
        pc.estado_id AS plan_estado_id

      FROM jugador_plan_catalogo jpc

      INNER JOIN jugadores j
        ON j.id = jpc.jugador_id
       AND j.academia_id = jpc.academia_id

      INNER JOIN tipo_pago tp
        ON tp.id = jpc.tipo_pago_id

      INNER JOIN planes_catalogo pc
        ON pc.id = jpc.plan_id

      WHERE jpc.id = ?
        AND jpc.academia_id = ?

      LIMIT 1
    `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

async function validateJugador(academiaId: number, jugadorId: number, executor: any = db) {
  const [rows]: any = await executor.query(
    `
      SELECT id
      FROM jugadores
      WHERE id = ?
        AND academia_id = ?
      LIMIT 1
    `,
    [jugadorId, academiaId]
  );

  if (!rows?.length) {
    throw businessError("El jugador no existe o no pertenece a la academia");
  }
}

type TarifaContext = {
  tarifa_id: number;
  tipo_pago_id: number;
  monto: number;
};

async function getTarifaOrThrow(academiaId: number, tipoPagoId: number, executor: any = db): Promise<TarifaContext> {
  const [rows]: any = await executor.query(
    `
      SELECT
        tp.id AS tipo_pago_id,
        tp.estado_id AS tipo_pago_estado_id,
        atp.estado_id AS academia_tipo_pago_estado_id,
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
        AND atp.tipo_pago_id = ?

      LIMIT 1
    `,
    [academiaId, tipoPagoId]
  );

  if (!rows?.length) {
    throw businessError("El tipo de pago no posee una tarifa configurada para la academia");
  }

  const row = rows[0];

  if (Number(row.tipo_pago_estado_id) !== ESTADO_ACTIVO) {
    throw businessError("El tipo de pago seleccionado no se encuentra activo");
  }

  if (Number(row.academia_tipo_pago_estado_id) !== ESTADO_ACTIVO) {
    throw businessError("El tipo de pago no se encuentra habilitado para la academia");
  }

  if (Number(row.tarifa_estado_id) !== ESTADO_ACTIVO) {
    throw businessError("La tarifa asociada al tipo de pago no se encuentra activa");
  }

  const monto = Number(row.monto);

  if (!Number.isFinite(monto) || monto < 0) {
    throw businessError("La tarifa configurada posee un monto inválido");
  }

  return {
    tarifa_id: Number(row.tarifa_id),
    tipo_pago_id: Number(row.tipo_pago_id),
    monto: roundMoney(monto),
  };
}

async function validateTipoPago(academiaId: number, tipoPagoId: number, executor: any = db) {
  return getTarifaOrThrow(academiaId, tipoPagoId, executor);
}

async function validatePlan(planId: number, executor: any = db) {
  const [rows]: any = await executor.query(
    `
      SELECT
        id,
        nombre,
        descripcion,
        estado_id

      FROM planes_catalogo

      WHERE id = ?

      LIMIT 1
    `,
    [planId]
  );

  if (!rows?.length) {
    throw businessError("El beneficio no existe en el catálogo global");
  }

  if (Number(rows[0].estado_id) !== ESTADO_ACTIVO) {
    throw businessError("El beneficio seleccionado no se encuentra activo en el catálogo global");
  }

  return rows[0];
}

async function getPlanRule(planId: number, executor: any = db) {
  const [rows]: any = await executor.query(
    `
      SELECT
        id,
        plan_id,
        tipo_beneficio,
        valor,
        estado_id

      FROM plan_reglas

      WHERE plan_id = ?
        AND estado_id = 1

      LIMIT 1
    `,
    [planId]
  );

  return rows?.length ? rows[0] : null;
}

function calculateAssignedAmount(montoTarifa: number, rule: any | null): number {
  const base = roundMoney(montoTarifa);

  if (!rule) {
    return base;
  }

  const tipo = String(rule.tipo_beneficio ?? "")
    .trim()
    .toUpperCase();

  const valor = Number(rule.valor);

  if (!Number.isFinite(valor) || valor < 0) {
    throw businessError("La regla del beneficio posee un valor inválido");
  }

  let montoAsignado = base;

  switch (tipo) {
    case "PORCENTAJE": {
      if (valor > 100) {
        throw businessError("El porcentaje del beneficio no puede ser superior a 100");
      }

      const descuento = roundMoney(base * (valor / 100));

      montoAsignado = roundMoney(base - Math.min(base, descuento));

      break;
    }

    case "DESCUENTO_FIJO": {
      const descuento = Math.min(base, roundMoney(valor));

      montoAsignado = roundMoney(base - descuento);

      break;
    }

    case "PRECIO_FIJO": {
      montoAsignado = roundMoney(Math.min(base, valor));

      break;
    }

    default: {
      throw businessError("Tipo de beneficio no soportado");
    }
  }

  if (montoAsignado < 0) {
    montoAsignado = 0;
  }

  if (montoAsignado > base) {
    montoAsignado = base;
  }

  return roundMoney(montoAsignado);
}

type FinancialSnapshot = {
  tarifa_id: number;
  monto_tarifa: number;
  monto_asignado: number;
};

async function buildFinancialSnapshot(
  academiaId: number,
  tipoPagoId: number,
  planId: number,
  executor: any = db
): Promise<FinancialSnapshot> {
  const tarifa = await getTarifaOrThrow(academiaId, tipoPagoId, executor);

  await validatePlan(planId, executor);

  const rule = await getPlanRule(planId, executor);

  const montoAsignado = calculateAssignedAmount(tarifa.monto, rule);

  return {
    tarifa_id: tarifa.tarifa_id,

    monto_tarifa: tarifa.monto,

    monto_asignado: montoAsignado,
  };
}

async function existsEquivalentAssignment(
  academiaId: number,
  jugadorId: number,
  tipoPagoId: number,
  planId: number,
  fechaInicio: string,
  fechaFin: string | null,
  excludeId?: number,
  executor: any = db
): Promise<boolean> {
  const params: any[] = [academiaId, jugadorId, tipoPagoId, planId, fechaInicio, fechaFin, fechaFin];

  let sql = `
    SELECT id
    FROM jugador_plan_catalogo
    WHERE academia_id = ?
      AND jugador_id = ?
      AND tipo_pago_id = ?
      AND plan_id = ?
      AND fecha_inicio = ?
      AND (
        (
          fecha_fin IS NULL
          AND ? IS NULL
        )
        OR fecha_fin = ?
      )
  `;

  if (excludeId !== undefined) {
    sql += `
      AND id <> ?
    `;

    params.push(excludeId);
  }

  sql += `
    LIMIT 1
  `;

  const [rows]: any = await executor.query(sql, params);

  return Array.isArray(rows) && rows.length > 0;
}

async function hasOverlappingActiveAssignment(
  academiaId: number,
  jugadorId: number,
  tipoPagoId: number,
  fechaInicio: string,
  fechaFin: string | null,
  excludeId?: number,
  executor: any = db
): Promise<boolean> {
  const params: any[] = [academiaId, jugadorId, tipoPagoId, fechaFin, fechaFin, fechaInicio];

  let sql = `
    SELECT id
    FROM jugador_plan_catalogo
    WHERE academia_id = ?
      AND jugador_id = ?
      AND tipo_pago_id = ?
      AND estado_id = 1
      AND (
        ? IS NULL
        OR fecha_inicio <= ?
      )
      AND (
        fecha_fin IS NULL
        OR fecha_fin >= ?
      )
  `;

  if (excludeId !== undefined) {
    sql += `
      AND id <> ?
    `;

    params.push(excludeId);
  }

  sql += `
    LIMIT 1
  `;

  const [rows]: any = await executor.query(sql, params);

  return Array.isArray(rows) && rows.length > 0;
}

async function hasPayments(
  academiaId: number,
  assignment: {
    jugador_id: number;
    plan_id: number;
    fecha_inicio: string;
    fecha_fin: string | null;
  },
  executor: any = db
): Promise<boolean> {
  const [rows]: any = await executor.query(
    `
        SELECT p.id

        FROM pagos_jugador p

        WHERE p.academia_id = ?
          AND p.jugador_id = ?
          AND p.plan_catalogo_id = ?
          AND p.fecha_pago >= ?
          AND (
            ? IS NULL
            OR p.fecha_pago <= ?
          )

        LIMIT 1
      `,
    [
      academiaId,
      assignment.jugador_id,
      assignment.plan_id,
      assignment.fecha_inicio,
      assignment.fecha_fin,
      assignment.fecha_fin,
    ]
  );

  return Array.isArray(rows) && rows.length > 0;
}

function protectedFieldsChanged(
  current: {
    jugador_id: number;
    tipo_pago_id: number;
    plan_id: number;
    fecha_inicio: string;
    fecha_fin: string | null;
  },
  next: {
    jugador_id: number;
    tipo_pago_id: number;
    plan_id: number;
    fecha_inicio: string;
    fecha_fin: string | null;
  }
): boolean {
  return (
    current.jugador_id !== next.jugador_id ||
    current.tipo_pago_id !== next.tipo_pago_id ||
    current.plan_id !== next.plan_id ||
    current.fecha_inicio !== next.fecha_inicio ||
    current.fecha_fin !== next.fecha_fin
  );
}

function financialIdentityChanged(
  current: {
    tipo_pago_id: number;
    plan_id: number;
  },
  next: {
    tipo_pago_id: number;
    plan_id: number;
  }
): boolean {
  return current.tipo_pago_id !== next.tipo_pago_id || current.plan_id !== next.plan_id;
}

function handleKnownError(reply: FastifyReply, err: any) {
  const status = Number(err?.statusCode ?? 0);

  if ([400, 401, 403, 404, 409].includes(status)) {
    reply.header("Cache-Control", "no-store");

    return reply.code(status).send({
      ok: false,

      message: err?.message ?? "No fue posible procesar la solicitud",
    });
  }

  return null;
}

export default async function jugador_planes(app: FastifyInstance) {
  const canRead = [requireAuth, requireRoles([1, 2, 3])];

  const canWrite = [requireAuth, requireRoles([1, 3])];

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
          module: "jugador_plan_catalogo",

          status: "ready",

          academia_id: academiaId,

          timestamp: new Date().toISOString(),
        });
      } catch (err: any) {
        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        reply.header("Cache-Control", "no-store");

        return reply.code(500).send({
          ok: false,

          message: "Error en módulo jugador_planes",

          detail: err?.message,
        });
      }
    }
  );

  app.get(
    "/",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const academiaId = resolveAcademiaId(req);

        const query = QuerySchema.parse(req.query);

        const where: string[] = ["jpc.academia_id = ?"];

        const values: any[] = [academiaId];

        if (query.jugador_id !== undefined) {
          where.push("jpc.jugador_id = ?");

          values.push(query.jugador_id);
        }

        if (query.tipo_pago_id !== undefined) {
          where.push("jpc.tipo_pago_id = ?");

          values.push(query.tipo_pago_id);
        }

        if (query.plan_id !== undefined) {
          where.push("jpc.plan_id = ?");

          values.push(query.plan_id);
        }

        if (query.estado_id !== undefined) {
          where.push("jpc.estado_id = ?");

          values.push(query.estado_id);
        }

        if (query.activos === "1") {
          where.push("jpc.estado_id = 1");

          where.push(
            `
              (
                jpc.fecha_fin IS NULL
                OR jpc.fecha_fin >= CURDATE()
              )
            `
          );
        }

        if (query.activos === "0") {
          where.push(
            `
              (
                jpc.estado_id <> 1
                OR (
                  jpc.fecha_fin IS NOT NULL
                  AND jpc.fecha_fin < CURDATE()
                )
              )
            `
          );
        }

        values.push(query.limit);

        const [rows]: any = await db.query(
          `
              SELECT
                jpc.id,
                jpc.academia_id,
                jpc.jugador_id,
                jpc.tipo_pago_id,
                jpc.plan_id,
                jpc.tarifa_id,
                jpc.monto_tarifa,
                jpc.monto_asignado,
                jpc.fecha_inicio,
                jpc.fecha_fin,
                jpc.estado_id,
                jpc.created_at,
                jpc.updated_at,

                j.nombre_jugador_enc
                  AS jugador_nombre_enc,

                j.rut_jugador_enc
                  AS jugador_rut_enc,

                tp.nombre
                  AS tipo_pago_nombre,

                pc.nombre
                  AS plan_nombre,

                pc.descripcion
                  AS plan_descripcion,

                pc.estado_id
                  AS plan_estado_id

              FROM jugador_plan_catalogo jpc

              INNER JOIN jugadores j
                ON j.id =
                   jpc.jugador_id
               AND j.academia_id =
                   jpc.academia_id

              INNER JOIN tipo_pago tp
                ON tp.id =
                   jpc.tipo_pago_id

              INNER JOIN planes_catalogo pc
                ON pc.id =
                   jpc.plan_id

              WHERE
                ${where.join(" AND ")}

              ORDER BY
                jpc.fecha_inicio DESC,
                tp.nombre ASC,
                jpc.id DESC

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

        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al listar beneficios de jugadores",

          detail: err?.message,
        });
      }
    }
  );

  app.post(
    "/tipos-pago/bulk",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      let conn: any = null;

      try {
        const academiaId = resolveAcademiaId(req);

        const body = BulkSchema.parse(req.body);

        validateDates(body.fecha_inicio, body.fecha_fin);

        const tipoPagoIds = body.items.map((item) => Number(item.tipo_pago_id));

        if (new Set(tipoPagoIds).size !== tipoPagoIds.length) {
          throw businessError("No se puede configurar el mismo tipo de pago más de una vez");
        }

        conn = await db.getConnection();

        await conn.beginTransaction();

        await validateJugador(academiaId, body.jugador_id, conn);

        const createdIds: number[] = [];

        for (const item of body.items) {
          const tipoPagoId = Number(item.tipo_pago_id);

          const planId = Number(item.plan_id);

          const snapshot = await buildFinancialSnapshot(academiaId, tipoPagoId, planId, conn);

          const equivalent = await existsEquivalentAssignment(
            academiaId,
            body.jugador_id,
            tipoPagoId,
            planId,
            body.fecha_inicio,
            body.fecha_fin,
            undefined,
            conn
          );

          if (equivalent) {
            throw businessError(`Ya existe una asignación equivalente para el tipo de pago ${tipoPagoId}`, 409);
          }

          if (Number(body.estado_id) === ESTADO_ACTIVO) {
            const overlapping = await hasOverlappingActiveAssignment(
              academiaId,
              body.jugador_id,
              tipoPagoId,
              body.fecha_inicio,
              body.fecha_fin,
              undefined,
              conn
            );

            if (overlapping) {
              throw businessError(
                `El jugador ya posee un beneficio activo para el tipo de pago ${tipoPagoId} durante el período indicado`,
                409
              );
            }
          }

          const [result]: any = await conn.query(
            `
                INSERT INTO jugador_plan_catalogo (
                  academia_id,
                  jugador_id,
                  tipo_pago_id,
                  plan_id,
                  tarifa_id,
                  monto_tarifa,
                  monto_asignado,
                  fecha_inicio,
                  fecha_fin,
                  estado_id
                )
                VALUES (
                  ?,
                  ?,
                  ?,
                  ?,
                  ?,
                  ?,
                  ?,
                  ?,
                  ?,
                  ?
                )
              `,
            [
              academiaId,
              body.jugador_id,
              tipoPagoId,
              planId,

              snapshot.tarifa_id,
              snapshot.monto_tarifa,
              snapshot.monto_asignado,

              body.fecha_inicio,
              body.fecha_fin,
              body.estado_id,
            ]
          );

          const insertId = Number(result?.insertId);

          if (!Number.isInteger(insertId) || insertId <= 0) {
            throw new Error("No fue posible obtener el ID de una asignación creada");
          }

          createdIds.push(insertId);
        }

        const placeholders = createdIds.map(() => "?").join(", ");

        const [rows]: any = await conn.query(
          `
              SELECT
                jpc.id,
                jpc.academia_id,
                jpc.jugador_id,
                jpc.tipo_pago_id,
                jpc.plan_id,
                jpc.tarifa_id,
                jpc.monto_tarifa,
                jpc.monto_asignado,
                jpc.fecha_inicio,
                jpc.fecha_fin,
                jpc.estado_id,
                jpc.created_at,
                jpc.updated_at,

                j.nombre_jugador_enc
                  AS jugador_nombre_enc,

                j.rut_jugador_enc
                  AS jugador_rut_enc,

                tp.nombre
                  AS tipo_pago_nombre,

                pc.nombre
                  AS plan_nombre,

                pc.descripcion
                  AS plan_descripcion,

                pc.estado_id
                  AS plan_estado_id

              FROM jugador_plan_catalogo jpc

              INNER JOIN jugadores j
                ON j.id =
                   jpc.jugador_id
               AND j.academia_id =
                   jpc.academia_id

              INNER JOIN tipo_pago tp
                ON tp.id =
                   jpc.tipo_pago_id

              INNER JOIN planes_catalogo pc
                ON pc.id =
                   jpc.plan_id

              WHERE jpc.academia_id = ?
                AND jpc.id
                  IN (
                    ${placeholders}
                  )

              ORDER BY
                tp.nombre ASC,
                jpc.id ASC
            `,
          [academiaId, ...createdIds]
        );

        await conn.commit();

        reply.header("Cache-Control", "no-store");

        return reply.code(201).send({
          ok: true,

          academia_id: academiaId,

          jugador_id: body.jugador_id,

          count: rows?.length ?? 0,

          items: (rows ?? []).map(normalize),
        });
      } catch (err: any) {
        if (conn) {
          try {
            await conn.rollback();
          } catch {}
        }

        reply.header("Cache-Control", "no-store");

        if (err instanceof ZodError) {
          return reply.code(400).send({
            ok: false,

            message: "Payload inválido",

            detail: zodDetail(err),
          });
        }

        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "Una de las asignaciones de beneficio ya existe",
          });
        }

        if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
          return reply.code(409).send({
            ok: false,

            message: "Uno o más datos relacionados no existen",
          });
        }

        console.error("[jugador_planes] POST /tipos-pago/bulk", err);

        return reply.code(500).send({
          ok: false,

          message: "Error al guardar beneficios por tipo de pago",

          detail: err?.message,
        });
      } finally {
        if (conn) {
          conn.release();
        }
      }
    }
  );

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

        const row = await getJugadorPlan(academiaId, parsed.data.id);

        reply.header("Cache-Control", "no-store");

        if (!row) {
          return reply.code(404).send({
            ok: false,

            message: "Asignación de beneficio no encontrada",
          });
        }

        return reply.send({
          ok: true,

          item: normalize(row),
        });
      } catch (err: any) {
        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        reply.header("Cache-Control", "no-store");

        return reply.code(500).send({
          ok: false,

          message: "Error al obtener asignación de beneficio",

          detail: err?.message,
        });
      }
    }
  );

  app.post(
    "/",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      let conn: any = null;

      try {
        const academiaId = resolveAcademiaId(req);

        const body = CreateSchema.parse(req.body);

        validateDates(body.fecha_inicio, body.fecha_fin);

        conn = await db.getConnection();

        await conn.beginTransaction();

        await validateJugador(academiaId, body.jugador_id, conn);

        const snapshot = await buildFinancialSnapshot(academiaId, body.tipo_pago_id, body.plan_id, conn);

        const equivalent = await existsEquivalentAssignment(
          academiaId,
          body.jugador_id,
          body.tipo_pago_id,
          body.plan_id,
          body.fecha_inicio,
          body.fecha_fin,
          undefined,
          conn
        );

        if (equivalent) {
          throw businessError("Ya existe una asignación equivalente para este jugador, tipo de pago y beneficio", 409);
        }

        if (Number(body.estado_id) === ESTADO_ACTIVO) {
          const overlapping = await hasOverlappingActiveAssignment(
            academiaId,
            body.jugador_id,
            body.tipo_pago_id,
            body.fecha_inicio,
            body.fecha_fin,
            undefined,
            conn
          );

          if (overlapping) {
            throw businessError(
              "El jugador ya posee otro beneficio activo para este tipo de pago durante el período indicado",
              409
            );
          }
        }

        const [result]: any = await conn.query(
          `
              INSERT INTO jugador_plan_catalogo (
                academia_id,
                jugador_id,
                tipo_pago_id,
                plan_id,
                tarifa_id,
                monto_tarifa,
                monto_asignado,
                fecha_inicio,
                fecha_fin,
                estado_id
              )
              VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?
              )
            `,
          [
            academiaId,
            body.jugador_id,
            body.tipo_pago_id,
            body.plan_id,

            snapshot.tarifa_id,
            snapshot.monto_tarifa,
            snapshot.monto_asignado,

            body.fecha_inicio,
            body.fecha_fin,
            body.estado_id,
          ]
        );

        const insertId = Number(result?.insertId);

        if (!Number.isInteger(insertId) || insertId <= 0) {
          throw new Error("No fue posible obtener el ID de la asignación creada");
        }

        const row = await getJugadorPlan(academiaId, insertId, conn);

        await conn.commit();

        reply.header("Cache-Control", "no-store");

        return reply.code(201).send({
          ok: true,

          id: insertId,

          item: row ? normalize(row) : null,
        });
      } catch (err: any) {
        if (conn) {
          try {
            await conn.rollback();
          } catch {}
        }

        reply.header("Cache-Control", "no-store");

        if (err instanceof ZodError) {
          return reply.code(400).send({
            ok: false,

            message: "Payload inválido",

            detail: zodDetail(err),
          });
        }

        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "La asignación de beneficio ya existe",
          });
        }

        if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
          return reply.code(409).send({
            ok: false,

            message: "Uno o más datos relacionados no existen",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al asignar beneficio al jugador",

          detail: err?.message,
        });
      } finally {
        if (conn) {
          conn.release();
        }
      }
    }
  );

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

      let conn: any = null;

      try {
        const academiaId = resolveAcademiaId(req);

        const id = parsed.data.id;

        const body = PutSchema.parse(req.body);

        validateDates(body.fecha_inicio, body.fecha_fin);

        conn = await db.getConnection();

        await conn.beginTransaction();

        const current = await getJugadorPlan(academiaId, id, conn);

        if (!current) {
          throw businessError("Asignación de beneficio no encontrada", 404);
        }

        const currentAssignment = {
          jugador_id: Number(current.jugador_id),

          tipo_pago_id: Number(current.tipo_pago_id),

          plan_id: Number(current.plan_id),

          fecha_inicio: normalizeSqlDate(current.fecha_inicio)!,

          fecha_fin: normalizeSqlDate(current.fecha_fin),
        };

        const nextAssignment = {
          jugador_id: Number(body.jugador_id),

          tipo_pago_id: Number(body.tipo_pago_id),

          plan_id: Number(body.plan_id),

          fecha_inicio: body.fecha_inicio,

          fecha_fin: body.fecha_fin,
        };

        const payments = await hasPayments(academiaId, currentAssignment, conn);

        if (payments && protectedFieldsChanged(currentAssignment, nextAssignment)) {
          throw businessError(
            "La asignación posee historial financiero asociado; no se puede modificar jugador, tipo de pago, beneficio ni período de vigencia. Solo puede modificarse estado_id",
            409
          );
        }

        await validateJugador(academiaId, body.jugador_id, conn);

        await validateTipoPago(academiaId, body.tipo_pago_id, conn);

        await validatePlan(body.plan_id, conn);

        const equivalent = await existsEquivalentAssignment(
          academiaId,
          body.jugador_id,
          body.tipo_pago_id,
          body.plan_id,
          body.fecha_inicio,
          body.fecha_fin,
          id,
          conn
        );

        if (equivalent) {
          throw businessError("Ya existe otra asignación equivalente para este jugador, tipo de pago y beneficio", 409);
        }

        if (Number(body.estado_id) === ESTADO_ACTIVO) {
          const overlapping = await hasOverlappingActiveAssignment(
            academiaId,
            body.jugador_id,
            body.tipo_pago_id,
            body.fecha_inicio,
            body.fecha_fin,
            id,
            conn
          );

          if (overlapping) {
            throw businessError(
              "El jugador ya posee otro beneficio activo para este tipo de pago durante el período indicado",
              409
            );
          }
        }

        let tarifaId = Number(current.tarifa_id);

        let montoTarifa = roundMoney(Number(current.monto_tarifa));

        let montoAsignado = roundMoney(Number(current.monto_asignado));

        if (financialIdentityChanged(currentAssignment, nextAssignment)) {
          const snapshot = await buildFinancialSnapshot(academiaId, body.tipo_pago_id, body.plan_id, conn);

          tarifaId = snapshot.tarifa_id;

          montoTarifa = snapshot.monto_tarifa;

          montoAsignado = snapshot.monto_asignado;
        }

        const [result]: any = await conn.query(
          `
              UPDATE jugador_plan_catalogo
              SET
                jugador_id = ?,
                tipo_pago_id = ?,
                plan_id = ?,
                tarifa_id = ?,
                monto_tarifa = ?,
                monto_asignado = ?,
                fecha_inicio = ?,
                fecha_fin = ?,
                estado_id = ?
              WHERE id = ?
                AND academia_id = ?
              LIMIT 1
            `,
          [
            body.jugador_id,
            body.tipo_pago_id,
            body.plan_id,

            tarifaId,
            montoTarifa,
            montoAsignado,

            body.fecha_inicio,
            body.fecha_fin,
            body.estado_id,

            id,
            academiaId,
          ]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          throw businessError("Asignación de beneficio no encontrada", 404);
        }

        const updated = await getJugadorPlan(academiaId, id, conn);

        await conn.commit();

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          updated: updated ? normalize(updated) : null,
        });
      } catch (err: any) {
        if (conn) {
          try {
            await conn.rollback();
          } catch {}
        }

        reply.header("Cache-Control", "no-store");

        if (err instanceof ZodError) {
          return reply.code(400).send({
            ok: false,

            message: "Payload inválido",

            detail: zodDetail(err),
          });
        }

        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "La asignación de beneficio ya existe",
          });
        }

        if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
          return reply.code(409).send({
            ok: false,

            message: "Uno o más datos relacionados no existen",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al actualizar asignación de beneficio",

          detail: err?.message,
        });
      } finally {
        if (conn) {
          conn.release();
        }
      }
    }
  );

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

      let conn: any = null;

      try {
        const academiaId = resolveAcademiaId(req);

        const id = parsed.data.id;

        const body = PatchSchema.parse(req.body);

        if (Object.keys(body).length === 0) {
          throw businessError("No hay campos para actualizar");
        }

        conn = await db.getConnection();

        await conn.beginTransaction();

        const current = await getJugadorPlan(academiaId, id, conn);

        if (!current) {
          throw businessError("Asignación de beneficio no encontrada", 404);
        }

        const currentAssignment = {
          jugador_id: Number(current.jugador_id),

          tipo_pago_id: Number(current.tipo_pago_id),

          plan_id: Number(current.plan_id),

          fecha_inicio: normalizeSqlDate(current.fecha_inicio)!,

          fecha_fin: normalizeSqlDate(current.fecha_fin),
        };

        const merged = {
          jugador_id: body.jugador_id !== undefined ? Number(body.jugador_id) : currentAssignment.jugador_id,

          tipo_pago_id: body.tipo_pago_id !== undefined ? Number(body.tipo_pago_id) : currentAssignment.tipo_pago_id,

          plan_id: body.plan_id !== undefined ? Number(body.plan_id) : currentAssignment.plan_id,

          fecha_inicio: body.fecha_inicio !== undefined ? body.fecha_inicio : currentAssignment.fecha_inicio,

          fecha_fin: body.fecha_fin !== undefined ? body.fecha_fin : currentAssignment.fecha_fin,

          estado_id: body.estado_id !== undefined ? Number(body.estado_id) : Number(current.estado_id),
        };

        validateDates(merged.fecha_inicio, merged.fecha_fin);

        const nextAssignment = {
          jugador_id: merged.jugador_id,

          tipo_pago_id: merged.tipo_pago_id,

          plan_id: merged.plan_id,

          fecha_inicio: merged.fecha_inicio,

          fecha_fin: merged.fecha_fin,
        };

        const payments = await hasPayments(academiaId, currentAssignment, conn);

        if (payments && protectedFieldsChanged(currentAssignment, nextAssignment)) {
          throw businessError(
            "La asignación posee historial financiero asociado; no se puede modificar jugador, tipo de pago, beneficio ni período de vigencia. Solo puede modificarse estado_id",
            409
          );
        }

        await validateJugador(academiaId, merged.jugador_id, conn);

        await validateTipoPago(academiaId, merged.tipo_pago_id, conn);

        await validatePlan(merged.plan_id, conn);

        const equivalent = await existsEquivalentAssignment(
          academiaId,
          merged.jugador_id,
          merged.tipo_pago_id,
          merged.plan_id,
          merged.fecha_inicio,
          merged.fecha_fin,
          id,
          conn
        );

        if (equivalent) {
          throw businessError("Ya existe otra asignación equivalente para este jugador, tipo de pago y beneficio", 409);
        }

        if (merged.estado_id === ESTADO_ACTIVO) {
          const overlapping = await hasOverlappingActiveAssignment(
            academiaId,
            merged.jugador_id,
            merged.tipo_pago_id,
            merged.fecha_inicio,
            merged.fecha_fin,
            id,
            conn
          );

          if (overlapping) {
            throw businessError(
              "El jugador ya posee otro beneficio activo para este tipo de pago durante el período indicado",
              409
            );
          }
        }

        let tarifaId = Number(current.tarifa_id);

        let montoTarifa = roundMoney(Number(current.monto_tarifa));

        let montoAsignado = roundMoney(Number(current.monto_asignado));

        if (financialIdentityChanged(currentAssignment, nextAssignment)) {
          const snapshot = await buildFinancialSnapshot(academiaId, merged.tipo_pago_id, merged.plan_id, conn);

          tarifaId = snapshot.tarifa_id;

          montoTarifa = snapshot.monto_tarifa;

          montoAsignado = snapshot.monto_asignado;
        }

        const [result]: any = await conn.query(
          `
              UPDATE jugador_plan_catalogo
              SET
                jugador_id = ?,
                tipo_pago_id = ?,
                plan_id = ?,
                tarifa_id = ?,
                monto_tarifa = ?,
                monto_asignado = ?,
                fecha_inicio = ?,
                fecha_fin = ?,
                estado_id = ?
              WHERE id = ?
                AND academia_id = ?
              LIMIT 1
            `,
          [
            merged.jugador_id,
            merged.tipo_pago_id,
            merged.plan_id,

            tarifaId,
            montoTarifa,
            montoAsignado,

            merged.fecha_inicio,
            merged.fecha_fin,
            merged.estado_id,

            id,
            academiaId,
          ]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          throw businessError("Asignación de beneficio no encontrada", 404);
        }

        const updated = await getJugadorPlan(academiaId, id, conn);

        await conn.commit();

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          updated: updated ? normalize(updated) : null,
        });
      } catch (err: any) {
        if (conn) {
          try {
            await conn.rollback();
          } catch {}
        }

        reply.header("Cache-Control", "no-store");

        if (err instanceof ZodError) {
          return reply.code(400).send({
            ok: false,

            message: "Payload inválido",

            detail: zodDetail(err),
          });
        }

        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "La asignación de beneficio ya existe",
          });
        }

        if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
          return reply.code(409).send({
            ok: false,

            message: "Uno o más datos relacionados no existen",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al actualizar asignación de beneficio",

          detail: err?.message,
        });
      } finally {
        if (conn) {
          conn.release();
        }
      }
    }
  );

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

      let conn: any = null;

      try {
        const academiaId = resolveAcademiaId(req);

        const id = parsed.data.id;

        conn = await db.getConnection();

        await conn.beginTransaction();

        const current = await getJugadorPlan(academiaId, id, conn);

        if (!current) {
          throw businessError("Asignación de beneficio no encontrada", 404);
        }

        const assignment = {
          jugador_id: Number(current.jugador_id),

          plan_id: Number(current.plan_id),

          fecha_inicio: normalizeSqlDate(current.fecha_inicio)!,

          fecha_fin: normalizeSqlDate(current.fecha_fin),
        };

        if (await hasPayments(academiaId, assignment, conn)) {
          throw businessError(
            "La asignación posee historial financiero asociado y no puede eliminarse. Debe desactivarse mediante estado_id",
            409
          );
        }

        const [result]: any = await conn.query(
          `
              DELETE
              FROM jugador_plan_catalogo
              WHERE id = ?
                AND academia_id = ?
              LIMIT 1
            `,
          [id, academiaId]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          throw businessError("Asignación de beneficio no encontrada", 404);
        }

        await conn.commit();

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,
          deleted: id,
        });
      } catch (err: any) {
        if (conn) {
          try {
            await conn.rollback();
          } catch {}
        }

        reply.header("Cache-Control", "no-store");

        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1451 || String(err?.code ?? "").includes("ER_ROW_IS_REFERENCED")) {
          return reply.code(409).send({
            ok: false,

            message: "No se puede eliminar la asignación porque está en uso",

            detail: err?.sqlMessage ?? err?.message,
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al eliminar asignación de beneficio",

          detail: err?.message,
        });
      } finally {
        if (conn) {
          conn.release();
        }
      }
    }
  );
}
