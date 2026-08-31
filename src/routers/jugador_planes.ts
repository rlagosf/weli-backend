// src/routers/jugador_planes.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * Tabla: jugador_plan
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
 * Scope:
 * - Multi-academia
 *
 * Seguridad:
 * - READ: roles 1,2,3
 * - WRITE: roles 1,3
 *
 * academia_id:
 * - Admin/Staff: JWT firmado
 * - Superadmin: x-academia-id validado
 *
 * Reglas:
 * - academia_id nunca se acepta desde el body.
 * - jugador y plan deben pertenecer a la academia efectiva.
 * - no se permite duplicar una asignación activa equivalente.
 * - si existen cargos asociados, no se permite cambiar jugador/plan ni eliminar físicamente.
 */

/* =========================================================
   Schemas
========================================================= */

const IdParam = z.object({ id: z.coerce.number().int().positive() });

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
   Helpers
========================================================= */

function zodDetail(err: ZodError) {
  return err.issues.map((i) => `${i.path.join(".") || "field"}: ${i.message}`).join("; ");
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
    jugador_id: Number(row.jugador_id),
    plan_id: Number(row.plan_id),
    fecha_inicio: row.fecha_inicio ?? null,
    fecha_fin: row.fecha_fin ?? null,
    estado_id: Number(row.estado_id),
    jugador_nombre: row.jugador_nombre == null ? undefined : String(row.jugador_nombre),
    jugador_rut: row.jugador_rut == null ? undefined : Number(row.jugador_rut),
    plan_nombre: row.plan_nombre == null ? undefined : String(row.plan_nombre),
    periodicidad: row.periodicidad == null ? undefined : String(row.periodicidad),
    created_at: row.created_at ?? null,
    updated_at: row.updated_at ?? null,
  };
}

function validateDates(fechaInicio: string, fechaFin: string | null) {
  const inicio = new Date(`${fechaInicio}T00:00:00Z`);
  if (Number.isNaN(inicio.getTime())) throw new Error("fecha_inicio inválida");

  if (fechaFin !== null) {
    const fin = new Date(`${fechaFin}T00:00:00Z`);
    if (Number.isNaN(fin.getTime())) throw new Error("fecha_fin inválida");
    if (fin < inicio) throw new Error("fecha_fin no puede ser anterior a fecha_inicio");
  }
}

async function getJugadorPlan(academiaId: number, id: number) {
  const [rows]: any = await db.query(
    `
    SELECT
      jp.id, jp.academia_id, jp.jugador_id, jp.plan_id,
      jp.fecha_inicio, jp.fecha_fin, jp.estado_id,
      jp.created_at, jp.updated_at,
      j.nombre_jugador AS jugador_nombre,
      j.rut_jugador AS jugador_rut,
      pa.nombre AS plan_nombre,
      pa.periodicidad
    FROM jugador_plan jp
    INNER JOIN jugadores j ON j.id = jp.jugador_id AND j.academia_id = jp.academia_id
    INNER JOIN planes_academia pa ON pa.id = jp.plan_id AND pa.academia_id = jp.academia_id
    WHERE jp.id = ? AND jp.academia_id = ?
    LIMIT 1
    `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

async function validateJugador(academiaId: number, jugadorId: number) {
  const [rows]: any = await db.query(`SELECT id FROM jugadores WHERE id = ? AND academia_id = ? LIMIT 1`, [
    jugadorId,
    academiaId,
  ]);

  if (!rows?.length) throw new Error("El jugador no existe o no pertenece a la academia");
}

async function validatePlan(academiaId: number, planId: number) {
  const [rows]: any = await db.query(
    `
    SELECT id, estado_id
    FROM planes_academia
    WHERE id = ? AND academia_id = ?
    LIMIT 1
    `,
    [planId, academiaId]
  );

  if (!rows?.length) throw new Error("El plan no existe o no pertenece a la academia");
  if (Number(rows[0].estado_id) !== 1) throw new Error("El plan seleccionado no se encuentra activo");
}

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
    FROM jugador_plan
    WHERE academia_id = ?
      AND jugador_id = ?
      AND plan_id = ?
      AND fecha_inicio = ?
      AND (
        (fecha_fin IS NULL AND ? IS NULL)
        OR fecha_fin = ?
      )
  `;

  if (excludeId) {
    sql += ` AND id <> ?`;
    params.push(excludeId);
  }

  sql += ` LIMIT 1`;

  const [rows]: any = await db.query(sql, params);
  return Array.isArray(rows) && rows.length > 0;
}

async function hasActiveSamePlan(academiaId: number, jugadorId: number, planId: number, excludeId?: number) {
  const params: any[] = [academiaId, jugadorId, planId];

  let sql = `
    SELECT id
    FROM jugador_plan
    WHERE academia_id = ?
      AND jugador_id = ?
      AND plan_id = ?
      AND estado_id = 1
      AND (fecha_fin IS NULL OR fecha_fin >= CURDATE())
  `;

  if (excludeId) {
    sql += ` AND id <> ?`;
    params.push(excludeId);
  }

  sql += ` LIMIT 1`;

  const [rows]: any = await db.query(sql, params);
  return Array.isArray(rows) && rows.length > 0;
}

async function hasCargos(academiaId: number, jugadorPlanId: number) {
  const [rows]: any = await db.query(
    `
    SELECT id
    FROM cargos_jugador
    WHERE academia_id = ? AND jugador_plan_id = ?
    LIMIT 1
    `,
    [academiaId, jugadorPlanId]
  );

  return Array.isArray(rows) && rows.length > 0;
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
  const message = String(err?.message ?? "");

  return [
    "fecha_inicio inválida",
    "fecha_fin inválida",
    "fecha_fin no puede ser anterior a fecha_inicio",
    "El jugador no existe o no pertenece a la academia",
    "El plan no existe o no pertenece a la academia",
    "El plan seleccionado no se encuentra activo",
  ].includes(message);
}

/* =========================================================
   Router
========================================================= */

export default async function jugador_planes(app: FastifyInstance) {
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  /* =======================================================
     HEALTH
  ======================================================= */

  app.get("/health", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academiaId = resolveAcademiaId(req);

      reply.header("Cache-Control", "no-store");
      return reply.send({
        module: "jugador_plan",
        status: "ready",
        academia_id: academiaId,
        timestamp: new Date().toISOString(),
      });
    } catch (err: any) {
      const handled = handleScopeError(reply, err);
      if (handled) return handled;

      reply.header("Cache-Control", "no-store");
      return reply.code(500).send({ ok: false, message: "Error en módulo jugador_planes" });
    }
  });

  /* =======================================================
     GET /
  ======================================================= */

  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academiaId = resolveAcademiaId(req);
      const query = QuerySchema.parse(req.query);

      const where: string[] = ["jp.academia_id = ?"];
      const values: any[] = [academiaId];

      if (query.jugador_id !== undefined) {
        where.push("jp.jugador_id = ?");
        values.push(query.jugador_id);
      }

      if (query.plan_id !== undefined) {
        where.push("jp.plan_id = ?");
        values.push(query.plan_id);
      }

      if (query.estado_id !== undefined) {
        where.push("jp.estado_id = ?");
        values.push(query.estado_id);
      }

      if (query.activos === "1") {
        where.push("jp.estado_id = 1");
        where.push("(jp.fecha_fin IS NULL OR jp.fecha_fin >= CURDATE())");
      }

      if (query.activos === "0") {
        where.push("(jp.estado_id <> 1 OR (jp.fecha_fin IS NOT NULL AND jp.fecha_fin < CURDATE()))");
      }

      values.push(query.limit);

      const [rows]: any = await db.query(
        `
        SELECT
          jp.id, jp.academia_id, jp.jugador_id, jp.plan_id,
          jp.fecha_inicio, jp.fecha_fin, jp.estado_id,
          jp.created_at, jp.updated_at,
          j.nombre_jugador AS jugador_nombre,
          j.rut_jugador AS jugador_rut,
          pa.nombre AS plan_nombre,
          pa.periodicidad
        FROM jugador_plan jp
        INNER JOIN jugadores j ON j.id = jp.jugador_id AND j.academia_id = jp.academia_id
        INNER JOIN planes_academia pa ON pa.id = jp.plan_id AND pa.academia_id = jp.academia_id
        WHERE ${where.join(" AND ")}
        ORDER BY jp.fecha_inicio DESC, jp.id DESC
        LIMIT ?
        `,
        values
      );

      reply.header("Cache-Control", "no-store");
      return reply.send({ ok: true, count: rows?.length ?? 0, items: (rows ?? []).map(normalize) });
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
      if (handled) return handled;

      return reply.code(500).send({ ok: false, message: "Error al listar planes de jugadores" });
    }
  });

  /* =======================================================
     GET /:id
  ======================================================= */

  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);

    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const academiaId = resolveAcademiaId(req);
      const row = await getJugadorPlan(academiaId, parsed.data.id);

      reply.header("Cache-Control", "no-store");

      if (!row) return reply.code(404).send({ ok: false, message: "Asignación de plan no encontrada" });

      return reply.send({ ok: true, item: normalize(row) });
    } catch (err: any) {
      const handled = handleScopeError(reply, err);
      if (handled) return handled;

      reply.header("Cache-Control", "no-store");
      return reply.code(500).send({ ok: false, message: "Error al obtener asignación de plan" });
    }
  });

  /* =======================================================
     POST /
  ======================================================= */

  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
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
        INSERT INTO jugador_plan
          (academia_id, jugador_id, plan_id, fecha_inicio, fecha_fin, estado_id)
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
      if (handled) return handled;

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
        return reply.code(400).send({ ok: false, message: err.message });
      }

      return reply.code(500).send({ ok: false, message: "Error al asignar plan al jugador" });
    }
  });

  /* =======================================================
     PUT /:id
  ======================================================= */

  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);

    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const academiaId = resolveAcademiaId(req);
      const id = parsed.data.id;
      const current = await getJugadorPlan(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");
        return reply.code(404).send({ ok: false, message: "Asignación de plan no encontrada" });
      }

      const body = PutSchema.parse(req.body);
      const cargos = await hasCargos(academiaId, id);

      if (cargos && (Number(current.jugador_id) !== body.jugador_id || Number(current.plan_id) !== body.plan_id)) {
        reply.header("Cache-Control", "no-store");
        return reply.code(409).send({
          ok: false,
          message: "La asignación posee cargos asociados; no se puede cambiar el jugador ni el plan",
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
        UPDATE jugador_plan
        SET jugador_id = ?, plan_id = ?, fecha_inicio = ?, fecha_fin = ?, estado_id = ?
        WHERE id = ? AND academia_id = ?
        LIMIT 1
        `,
        [body.jugador_id, body.plan_id, body.fecha_inicio, body.fecha_fin, body.estado_id, id, academiaId]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "Asignación de plan no encontrada" });
      }

      const updated = await getJugadorPlan(academiaId, id);

      return reply.send({
        ok: true,
        updated: updated ? normalize(updated) : { id, academia_id: academiaId },
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
      if (handled) return handled;

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({
          ok: false,
          message: "La asignación de plan ya existe",
        });
      }

      if (isBusinessValidationError(err)) {
        return reply.code(400).send({ ok: false, message: err.message });
      }

      return reply.code(500).send({ ok: false, message: "Error al actualizar asignación de plan" });
    }
  });

  /* =======================================================
     PATCH /:id
  ======================================================= */

  app.patch("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);

    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const academiaId = resolveAcademiaId(req);
      const id = parsed.data.id;
      const current = await getJugadorPlan(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");
        return reply.code(404).send({ ok: false, message: "Asignación de plan no encontrada" });
      }

      const body = PatchSchema.parse(req.body);

      if (Object.keys(body).length === 0) {
        reply.header("Cache-Control", "no-store");
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
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

      const cargos = await hasCargos(academiaId, id);

      if (cargos && (merged.jugador_id !== Number(current.jugador_id) || merged.plan_id !== Number(current.plan_id))) {
        reply.header("Cache-Control", "no-store");
        return reply.code(409).send({
          ok: false,
          message: "La asignación posee cargos asociados; no se puede cambiar el jugador ni el plan",
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
        UPDATE jugador_plan
        SET jugador_id = ?, plan_id = ?, fecha_inicio = ?, fecha_fin = ?, estado_id = ?
        WHERE id = ? AND academia_id = ?
        LIMIT 1
        `,
        [merged.jugador_id, merged.plan_id, merged.fecha_inicio, merged.fecha_fin, merged.estado_id, id, academiaId]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "Asignación de plan no encontrada" });
      }

      const updated = await getJugadorPlan(academiaId, id);

      return reply.send({
        ok: true,
        updated: updated ? normalize(updated) : { id, academia_id: academiaId },
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
      if (handled) return handled;

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({
          ok: false,
          message: "La asignación de plan ya existe",
        });
      }

      if (isBusinessValidationError(err)) {
        return reply.code(400).send({ ok: false, message: err.message });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar asignación de plan",
      });
    }
  });

  /* =======================================================
     DELETE /:id
  ======================================================= */

  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse(req.params);

    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const academiaId = resolveAcademiaId(req);
      const id = parsed.data.id;

      const current = await getJugadorPlan(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");
        return reply.code(404).send({ ok: false, message: "Asignación de plan no encontrada" });
      }

      if (await hasCargos(academiaId, id)) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La asignación posee cargos asociados y no puede eliminarse",
        });
      }

      const [result]: any = await db.query(
        `
        DELETE FROM jugador_plan
        WHERE id = ? AND academia_id = ?
        LIMIT 1
        `,
        [id, academiaId]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "Asignación de plan no encontrada" });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      const handled = handleScopeError(reply, err);
      if (handled) return handled;

      if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
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
  });
}
