// src/routers/jugador_planes.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z, ZodError } from "zod";

import { db } from "../db";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * Tabla: jugador_plan_catalogo
 *
 * Campos:
 * - id
 * - academia_id
 * - jugador_id
 * - plan_id
 * - fecha_inicio
 * - fecha_fin
 * - estado_id
 * - created_at
 * - updated_at
 *
 * Modelo:
 *
 * planes_catalogo
 *        │
 *        └── academia_plan
 *                 │
 *                 └── jugador_plan_catalogo
 *
 * Seguridad:
 * - READ: roles 1, 2, 3
 * - WRITE: roles 1, 3
 *
 * academia_id:
 * - Admin/Staff: JWT firmado.
 * - Superadmin: x-academia-id validado.
 *
 * Reglas:
 * - academia_id nunca se acepta desde el body.
 * - jugador debe pertenecer a la academia efectiva.
 * - plan_id referencia planes_catalogo.
 * - el plan debe estar habilitado y activo en academia_plan.
 * - no se permite duplicar una asignación equivalente.
 * - no se permite mantener dos asignaciones activas
 *   simultáneas del mismo plan para un mismo jugador.
 * - si existe historial financiero asociado a la asignación,
 *   no se permite cambiar jugador/plan ni eliminarla físicamente.
 */

/* =========================================================
   SCHEMAS
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const DateString = z
  .string()
  .trim()
  .regex(/^\d{4}-\d{2}-\d{2}$/, "Fecha inválida. Formato esperado: YYYY-MM-DD");

const CreateSchema = z
  .object({
    jugador_id: z.coerce.number().int().positive(),

    plan_id: z.coerce.number().int().positive(),

    fecha_inicio: DateString,

    fecha_fin: z.union([DateString, z.null()]).optional().default(null),

    estado_id: z.coerce.number().int().positive().max(255).default(1),
  })
  .strict();

const PutSchema = z
  .object({
    jugador_id: z.coerce.number().int().positive(),

    plan_id: z.coerce.number().int().positive(),

    fecha_inicio: DateString,

    fecha_fin: z.union([DateString, z.null()]),

    estado_id: z.coerce.number().int().positive().max(255),
  })
  .strict();

const PatchSchema = z
  .object({
    jugador_id: z.coerce.number().int().positive().optional(),

    plan_id: z.coerce.number().int().positive().optional(),

    fecha_inicio: DateString.optional(),

    fecha_fin: z.union([DateString, z.null()]).optional(),

    estado_id: z.coerce.number().int().positive().max(255).optional(),
  })
  .strict();

const QuerySchema = z
  .object({
    jugador_id: z.coerce.number().int().positive().optional(),

    plan_id: z.coerce.number().int().positive().optional(),

    estado_id: z.coerce.number().int().positive().max(255).optional(),

    activos: z.enum(["1", "0"]).optional(),

    limit: z.coerce.number().int().min(1).max(500).default(200),
  })
  .strict();

/* =========================================================
   HELPERS
========================================================= */

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
   NORMALIZACIÓN
========================================================= */

function normalize(row: any) {
  return {
    id: Number(row.id),

    academia_id: Number(row.academia_id),

    jugador_id: Number(row.jugador_id),

    plan_id: Number(row.plan_id),

    fecha_inicio: row.fecha_inicio ?? null,

    fecha_fin: row.fecha_fin ?? null,

    estado_id: Number(row.estado_id),

    jugador_nombre: row.jugador_nombre == null ? undefined : String(row.jugador_nombre),

    jugador_rut: row.jugador_rut == null ? undefined : Number(row.jugador_rut),

    plan_nombre: row.plan_nombre == null ? undefined : String(row.plan_nombre),

    plan_descripcion: row.plan_descripcion == null ? null : String(row.plan_descripcion),

    plan_estado_id: row.plan_estado_id == null ? undefined : Number(row.plan_estado_id),

    academia_plan_estado_id: row.academia_plan_estado_id == null ? undefined : Number(row.academia_plan_estado_id),

    created_at: row.created_at ?? null,

    updated_at: row.updated_at ?? null,
  };
}

/* =========================================================
   FECHAS
========================================================= */

function validateDates(fechaInicio: string, fechaFin: string | null): void {
  const inicio = new Date(`${fechaInicio}T00:00:00Z`);

  if (Number.isNaN(inicio.getTime())) {
    throw new Error("fecha_inicio inválida");
  }

  if (fechaFin !== null) {
    const fin = new Date(`${fechaFin}T00:00:00Z`);

    if (Number.isNaN(fin.getTime())) {
      throw new Error("fecha_fin inválida");
    }

    if (fin < inicio) {
      throw new Error("fecha_fin no puede ser anterior a fecha_inicio");
    }
  }
}

/* =========================================================
   OBTENER ASIGNACIÓN
========================================================= */

async function getJugadorPlan(academiaId: number, id: number) {
  const [rows]: any = await db.query(
    `
        SELECT
          jpc.id,
          jpc.academia_id,
          jpc.jugador_id,
          jpc.plan_id,
          jpc.fecha_inicio,
          jpc.fecha_fin,
          jpc.estado_id,
          jpc.created_at,
          jpc.updated_at,

          j.nombre_jugador
            AS jugador_nombre,

          j.rut_jugador
            AS jugador_rut,

          pc.nombre
            AS plan_nombre,

          pc.descripcion
            AS plan_descripcion,

          pc.estado_id
            AS plan_estado_id,

          ap.estado_id
            AS academia_plan_estado_id

        FROM jugador_plan_catalogo jpc

        INNER JOIN jugadores j
          ON j.id =
             jpc.jugador_id

         AND j.academia_id =
             jpc.academia_id

        INNER JOIN planes_catalogo pc
          ON pc.id =
             jpc.plan_id

        LEFT JOIN academia_plan ap
          ON ap.academia_id =
             jpc.academia_id

         AND ap.plan_id =
             jpc.plan_id

        WHERE jpc.id = ?
          AND jpc.academia_id = ?

        LIMIT 1
      `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

/* =========================================================
   VALIDAR JUGADOR
========================================================= */

async function validateJugador(academiaId: number, jugadorId: number) {
  const [rows]: any = await db.query(
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
    throw new Error("El jugador no existe o no pertenece a la academia");
  }
}

/* =========================================================
   VALIDAR PLAN
========================================================= */

/**
 * plan_id es ID de planes_catalogo.
 *
 * Además, el plan debe encontrarse habilitado
 * para la academia mediante academia_plan.
 */
async function validatePlan(academiaId: number, planId: number) {
  const [rows]: any = await db.query(
    `
        SELECT
          pc.id,
          pc.estado_id
            AS catalogo_estado_id,

          ap.estado_id
            AS academia_plan_estado_id

        FROM planes_catalogo pc

        INNER JOIN academia_plan ap
          ON ap.plan_id =
             pc.id

         AND ap.academia_id = ?

        WHERE pc.id = ?

        LIMIT 1
      `,
    [academiaId, planId]
  );

  if (!rows?.length) {
    throw new Error("El plan no existe o no está habilitado para la academia");
  }

  if (Number(rows[0].catalogo_estado_id) !== 1) {
    throw new Error("El plan seleccionado no se encuentra activo en el catálogo global");
  }

  if (Number(rows[0].academia_plan_estado_id) !== 1) {
    throw new Error("El plan seleccionado no se encuentra habilitado para la academia");
  }
}

/* =========================================================
   ASIGNACIÓN EQUIVALENTE
========================================================= */

async function existsEquivalentAssignment(
  academiaId: number,
  jugadorId: number,
  planId: number,
  fechaInicio: string,
  fechaFin: string | null,
  excludeId?: number
) {
  const params: any[] = [academiaId, jugadorId, planId, fechaInicio, fechaFin, fechaFin];

  let sql = `
    SELECT id

    FROM jugador_plan_catalogo

    WHERE academia_id = ?
      AND jugador_id = ?
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

  if (excludeId) {
    sql += `
      AND id <> ?
    `;

    params.push(excludeId);
  }

  sql += `
    LIMIT 1
  `;

  const [rows]: any = await db.query(sql, params);

  return Array.isArray(rows) && rows.length > 0;
}

/* =========================================================
   PLAN ACTIVO DUPLICADO
========================================================= */

async function hasActiveSamePlan(academiaId: number, jugadorId: number, planId: number, excludeId?: number) {
  const params: any[] = [academiaId, jugadorId, planId];

  let sql = `
    SELECT id

    FROM jugador_plan_catalogo

    WHERE academia_id = ?
      AND jugador_id = ?
      AND plan_id = ?
      AND estado_id = 1

      AND (
        fecha_fin IS NULL
        OR fecha_fin >= CURDATE()
      )
  `;

  if (excludeId) {
    sql += `
      AND id <> ?
    `;

    params.push(excludeId);
  }

  sql += `
    LIMIT 1
  `;

  const [rows]: any = await db.query(sql, params);

  return Array.isArray(rows) && rows.length > 0;
}

/* =========================================================
   DEPENDENCIAS FINANCIERAS
========================================================= */

/**
 * El modelo anterior usaba cargos_jugador.jugador_plan_id.
 *
 * Esa tabla ya no existe.
 *
 * En el modelo actual la trazabilidad financiera se encuentra
 * en pagos_jugador mediante:
 *
 * - academia_id
 * - jugador_id
 * - plan_catalogo_id
 * - fecha_pago
 *
 * Se considera que una asignación ya posee historial cuando
 * existe al menos un pago del jugador con el mismo plan dentro
 * del período de vigencia de la asignación.
 */
async function hasPayments(
  academiaId: number,
  assignment: {
    jugador_id: number;
    plan_id: number;
    fecha_inicio: string;
    fecha_fin: string | null;
  }
): Promise<boolean> {
  const [rows]: any = await db.query(
    `
        SELECT
          p.id

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

/* =========================================================
   ERRORES DE SCOPE
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
    "fecha_inicio inválida",
    "fecha_fin inválida",
    "fecha_fin no puede ser anterior a fecha_inicio",

    "El jugador no existe o no pertenece a la academia",

    "El plan no existe o no está habilitado para la academia",

    "El plan seleccionado no se encuentra activo en el catálogo global",

    "El plan seleccionado no se encuentra habilitado para la academia",
  ].includes(message);
}

/* =========================================================
   ROUTER
========================================================= */

export default async function jugador_planes(app: FastifyInstance) {
  /*
   * Seguridad conservada exactamente.
   */

  const canRead = [requireAuth, requireRoles([1, 2, 3])];

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
          module: "jugador_plan_catalogo",

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

          message: "Error en módulo jugador_planes",
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

        const where: string[] = ["jpc.academia_id = ?"];

        const values: any[] = [academiaId];

        if (query.jugador_id !== undefined) {
          where.push("jpc.jugador_id = ?");

          values.push(query.jugador_id);
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
            `(
              jpc.fecha_fin IS NULL
              OR jpc.fecha_fin >= CURDATE()
            )`
          );
        }

        if (query.activos === "0") {
          where.push(
            `(
              jpc.estado_id <> 1

              OR (
                jpc.fecha_fin IS NOT NULL
                AND jpc.fecha_fin < CURDATE()
              )
            )`
          );
        }

        values.push(query.limit);

        const [rows]: any = await db.query(
          `
              SELECT
                jpc.id,
                jpc.academia_id,
                jpc.jugador_id,
                jpc.plan_id,

                jpc.fecha_inicio,
                jpc.fecha_fin,
                jpc.estado_id,

                jpc.created_at,
                jpc.updated_at,

                j.nombre_jugador
                  AS jugador_nombre,

                j.rut_jugador
                  AS jugador_rut,

                pc.nombre
                  AS plan_nombre,

                pc.descripcion
                  AS plan_descripcion,

                pc.estado_id
                  AS plan_estado_id,

                ap.estado_id
                  AS academia_plan_estado_id

              FROM jugador_plan_catalogo jpc

              INNER JOIN jugadores j
                ON j.id =
                   jpc.jugador_id

               AND j.academia_id =
                   jpc.academia_id

              INNER JOIN planes_catalogo pc
                ON pc.id =
                   jpc.plan_id

              LEFT JOIN academia_plan ap
                ON ap.academia_id =
                   jpc.academia_id

               AND ap.plan_id =
                   jpc.plan_id

              WHERE
                ${where.join(" AND ")}

              ORDER BY
                jpc.fecha_inicio DESC,
                jpc.id DESC

              LIMIT ?
            `,
          values
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

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

          message: "Error al listar planes de jugadores",
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

        const row = await getJugadorPlan(academiaId, parsed.data.id);

        reply.header("Cache-Control", "no-store");

        if (!row) {
          return reply.code(404).send({
            ok: false,

            message: "Asignación de plan no encontrada",
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

          message: "Error al obtener asignación de plan",
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

        validateDates(body.fecha_inicio, body.fecha_fin);

        await validateJugador(academiaId, body.jugador_id);

        await validatePlan(academiaId, body.plan_id);

        const equivalent = await existsEquivalentAssignment(
          academiaId,
          body.jugador_id,
          body.plan_id,
          body.fecha_inicio,
          body.fecha_fin
        );

        if (equivalent) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "Ya existe una asignación equivalente para este jugador y plan",
          });
        }

        if (Number(body.estado_id) === 1) {
          const active = await hasActiveSamePlan(academiaId, body.jugador_id, body.plan_id);

          if (active) {
            reply.header("Cache-Control", "no-store");

            return reply.code(409).send({
              ok: false,

              message: "El jugador ya posee este plan activo",
            });
          }
        }

        const [result]: any = await db.query(
          `
              INSERT INTO jugador_plan_catalogo (
                academia_id,
                jugador_id,
                plan_id,
                fecha_inicio,
                fecha_fin,
                estado_id
              )

              VALUES (?, ?, ?, ?, ?, ?)
            `,
          [academiaId, body.jugador_id, body.plan_id, body.fecha_inicio, body.fecha_fin, body.estado_id]
        );

        const insertId = Number(result?.insertId);

        const row = await getJugadorPlan(academiaId, insertId);

        reply.header("Cache-Control", "no-store");

        return reply.code(201).send({
          ok: true,

          id: insertId,

          item: row
            ? normalize(row)
            : {
                id: insertId,

                academia_id: academiaId,

                jugador_id: body.jugador_id,

                plan_id: body.plan_id,

                fecha_inicio: body.fecha_inicio,

                fecha_fin: body.fecha_fin,

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

            message: "La asignación de plan ya existe",
          });
        }

        if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
          return reply.code(409).send({
            ok: false,

            message: "Uno o más datos relacionados no existen",
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

          message: "Error al asignar plan al jugador",
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

        const current = await getJugadorPlan(academiaId, id);

        if (!current) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Asignación de plan no encontrada",
          });
        }

        const body = PutSchema.parse(req.body);

        const currentAssignment = {
          jugador_id: Number(current.jugador_id),

          plan_id: Number(current.plan_id),

          fecha_inicio: String(current.fecha_inicio).slice(0, 10),

          fecha_fin: current.fecha_fin == null ? null : String(current.fecha_fin).slice(0, 10),
        };

        const payments = await hasPayments(academiaId, currentAssignment);

        if (payments && (Number(current.jugador_id) !== body.jugador_id || Number(current.plan_id) !== body.plan_id)) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "La asignación posee historial financiero asociado; no se puede cambiar el jugador ni el plan",
          });
        }

        validateDates(body.fecha_inicio, body.fecha_fin);

        await validateJugador(academiaId, body.jugador_id);

        await validatePlan(academiaId, body.plan_id);

        const equivalent = await existsEquivalentAssignment(
          academiaId,
          body.jugador_id,
          body.plan_id,
          body.fecha_inicio,
          body.fecha_fin,
          id
        );

        if (equivalent) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "Ya existe otra asignación equivalente para este jugador y plan",
          });
        }

        if (body.estado_id === 1) {
          const active = await hasActiveSamePlan(academiaId, body.jugador_id, body.plan_id, id);

          if (active) {
            reply.header("Cache-Control", "no-store");

            return reply.code(409).send({
              ok: false,

              message: "El jugador ya posee este plan activo",
            });
          }
        }

        const [result]: any = await db.query(
          `
              UPDATE jugador_plan_catalogo

              SET
                jugador_id = ?,
                plan_id = ?,
                fecha_inicio = ?,
                fecha_fin = ?,
                estado_id = ?

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [body.jugador_id, body.plan_id, body.fecha_inicio, body.fecha_fin, body.estado_id, id, academiaId]
        );

        reply.header("Cache-Control", "no-store");

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,

            message: "Asignación de plan no encontrada",
          });
        }

        const updated = await getJugadorPlan(academiaId, id);

        return reply.send({
          ok: true,

          updated: updated
            ? normalize(updated)
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

        const handled = handleScopeError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "La asignación de plan ya existe",
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

          message: "Error al actualizar asignación de plan",
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

        const current = await getJugadorPlan(academiaId, id);

        if (!current) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Asignación de plan no encontrada",
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
          jugador_id: body.jugador_id ?? Number(current.jugador_id),

          plan_id: body.plan_id ?? Number(current.plan_id),

          fecha_inicio: body.fecha_inicio ?? String(current.fecha_inicio).slice(0, 10),

          fecha_fin:
            body.fecha_fin !== undefined
              ? body.fecha_fin
              : current.fecha_fin == null
                ? null
                : String(current.fecha_fin).slice(0, 10),

          estado_id: body.estado_id ?? Number(current.estado_id),
        };

        const currentAssignment = {
          jugador_id: Number(current.jugador_id),

          plan_id: Number(current.plan_id),

          fecha_inicio: String(current.fecha_inicio).slice(0, 10),

          fecha_fin: current.fecha_fin == null ? null : String(current.fecha_fin).slice(0, 10),
        };

        const payments = await hasPayments(academiaId, currentAssignment);

        if (
          payments &&
          (merged.jugador_id !== Number(current.jugador_id) || merged.plan_id !== Number(current.plan_id))
        ) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "La asignación posee historial financiero asociado; no se puede cambiar el jugador ni el plan",
          });
        }

        validateDates(merged.fecha_inicio, merged.fecha_fin);

        await validateJugador(academiaId, merged.jugador_id);

        await validatePlan(academiaId, merged.plan_id);

        const equivalent = await existsEquivalentAssignment(
          academiaId,
          merged.jugador_id,
          merged.plan_id,
          merged.fecha_inicio,
          merged.fecha_fin,
          id
        );

        if (equivalent) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "Ya existe otra asignación equivalente para este jugador y plan",
          });
        }

        if (merged.estado_id === 1) {
          const active = await hasActiveSamePlan(academiaId, merged.jugador_id, merged.plan_id, id);

          if (active) {
            reply.header("Cache-Control", "no-store");

            return reply.code(409).send({
              ok: false,

              message: "El jugador ya posee este plan activo",
            });
          }
        }

        const [result]: any = await db.query(
          `
              UPDATE jugador_plan_catalogo

              SET
                jugador_id = ?,
                plan_id = ?,
                fecha_inicio = ?,
                fecha_fin = ?,
                estado_id = ?

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [merged.jugador_id, merged.plan_id, merged.fecha_inicio, merged.fecha_fin, merged.estado_id, id, academiaId]
        );

        reply.header("Cache-Control", "no-store");

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,

            message: "Asignación de plan no encontrada",
          });
        }

        const updated = await getJugadorPlan(academiaId, id);

        return reply.send({
          ok: true,

          updated: updated
            ? normalize(updated)
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

        const handled = handleScopeError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "La asignación de plan ya existe",
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

          message: "Error al actualizar asignación de plan",
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

        const current = await getJugadorPlan(academiaId, id);

        if (!current) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,

            message: "Asignación de plan no encontrada",
          });
        }

        const assignment = {
          jugador_id: Number(current.jugador_id),

          plan_id: Number(current.plan_id),

          fecha_inicio: String(current.fecha_inicio).slice(0, 10),

          fecha_fin: current.fecha_fin == null ? null : String(current.fecha_fin).slice(0, 10),
        };

        if (await hasPayments(academiaId, assignment)) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message:
              "La asignación posee historial financiero asociado y no puede eliminarse. Debe desactivarse mediante estado_id",
          });
        }

        const [result]: any = await db.query(
          `
              DELETE
              FROM jugador_plan_catalogo

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

            message: "Asignación de plan no encontrada",
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

            message: "No se puede eliminar la asignación porque está en uso",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al eliminar asignación de plan",
        });
      }
    }
  );
}
