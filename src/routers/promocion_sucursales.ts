// src/routers/promocion_sucursales.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * Tabla: promocion_sucursal
 *
 * Campos:
 * - id
 * - academia_id
 * - promocion_id
 * - sucursal_id
 * - created_at
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
 * - promocion_id debe pertenecer a la academia efectiva.
 * - sucursal_id debe pertenecer a la academia efectiva.
 * - no se permite duplicar promocion_id + sucursal_id.
 * - si esta relación fue utilizada en cargos históricos,
 *   no puede transformarse ni eliminarse.
 */

/* =========================================================
   Schemas
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    promocion_id: z.coerce.number().int().positive(),
    sucursal_id: z.coerce.number().int().positive(),
  })
  .strict();

const PutSchema = z
  .object({
    promocion_id: z.coerce.number().int().positive(),
    sucursal_id: z.coerce.number().int().positive(),
  })
  .strict();

const PatchSchema = z
  .object({
    promocion_id: z.coerce.number().int().positive().optional(),
    sucursal_id: z.coerce.number().int().positive().optional(),
  })
  .strict();

const QuerySchema = z
  .object({
    promocion_id: z.coerce.number().int().positive().optional(),
    sucursal_id: z.coerce.number().int().positive().optional(),
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
    promocion_id: Number(row.promocion_id),
    sucursal_id: Number(row.sucursal_id),

    promocion_nombre: row.promocion_nombre == null ? undefined : String(row.promocion_nombre),
    tipo_beneficio: row.tipo_beneficio == null ? undefined : String(row.tipo_beneficio),
    valor: row.valor == null ? undefined : Number(row.valor),

    fecha_desde: row.fecha_desde ?? undefined,
    fecha_hasta: row.fecha_hasta ?? undefined,
    promocion_estado_id: row.promocion_estado_id == null ? undefined : Number(row.promocion_estado_id),

    sucursal_nombre: row.sucursal_nombre == null ? undefined : String(row.sucursal_nombre),

    created_at: row.created_at ?? null,
  };
}

async function getPromocionSucursal(academiaId: number, id: number) {
  const [rows]: any = await db.query(
    `
    SELECT
      ps.id,
      ps.academia_id,
      ps.promocion_id,
      ps.sucursal_id,
      ps.created_at,

      p.nombre AS promocion_nombre,
      p.tipo_beneficio,
      p.valor,
      p.fecha_desde,
      p.fecha_hasta,
      p.estado_id AS promocion_estado_id,

      sr.nombre AS sucursal_nombre

    FROM promocion_sucursal ps

    INNER JOIN promociones_academia p
      ON p.id = ps.promocion_id
     AND p.academia_id = ps.academia_id

    INNER JOIN sucursales_real sr
      ON sr.id = ps.sucursal_id
     AND sr.academia_id = ps.academia_id

    WHERE ps.id = ?
      AND ps.academia_id = ?

    LIMIT 1
    `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

async function validatePromocion(academiaId: number, promocionId: number) {
  const [rows]: any = await db.query(
    `
    SELECT id
    FROM promociones_academia
    WHERE id = ?
      AND academia_id = ?
    LIMIT 1
    `,
    [promocionId, academiaId]
  );

  if (!rows?.length) {
    throw new Error("La promoción no existe o no pertenece a la academia");
  }
}

async function validateSucursal(academiaId: number, sucursalId: number) {
  const [rows]: any = await db.query(
    `
    SELECT id
    FROM sucursales_real
    WHERE id = ?
      AND academia_id = ?
    LIMIT 1
    `,
    [sucursalId, academiaId]
  );

  if (!rows?.length) {
    throw new Error("La sucursal no existe o no pertenece a la academia");
  }
}

async function existsRelation(academiaId: number, promocionId: number, sucursalId: number, excludeId?: number) {
  const values: any[] = [academiaId, promocionId, sucursalId];

  let sql = `
    SELECT id
    FROM promocion_sucursal
    WHERE academia_id = ?
      AND promocion_id = ?
      AND sucursal_id = ?
  `;

  if (excludeId) {
    sql += ` AND id <> ?`;
    values.push(excludeId);
  }

  sql += ` LIMIT 1`;

  const [rows]: any = await db.query(sql, values);
  return Array.isArray(rows) && rows.length > 0;
}

/**
 * Determina si la combinación promoción + sucursal
 * ya fue utilizada efectivamente en algún cargo.
 *
 * cargos_jugador almacena ambos datos:
 * - promocion_id
 * - sucursal_id
 */
async function relationHasCargos(academiaId: number, promocionId: number, sucursalId: number) {
  const [rows]: any = await db.query(
    `
    SELECT id
    FROM cargos_jugador
    WHERE academia_id = ?
      AND promocion_id = ?
      AND sucursal_id = ?
    LIMIT 1
    `,
    [academiaId, promocionId, sucursalId]
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
  return [
    "La promoción no existe o no pertenece a la academia",
    "La sucursal no existe o no pertenece a la academia",
  ].includes(String(err?.message ?? ""));
}

/* =========================================================
   Router
========================================================= */

export default async function promocion_sucursales(app: FastifyInstance) {
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
        module: "promocion_sucursal",
        status: "ready",
        academia_id: academiaId,
        timestamp: new Date().toISOString(),
      });
    } catch (err: any) {
      const handled = handleScopeError(reply, err);
      if (handled) return handled;

      reply.header("Cache-Control", "no-store");

      return reply.code(500).send({
        ok: false,
        message: "Error en módulo promocion_sucursales",
      });
    }
  });

  /* =======================================================
     GET /
  ======================================================= */

  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academiaId = resolveAcademiaId(req);
      const query = QuerySchema.parse(req.query);

      const where: string[] = ["ps.academia_id = ?"];
      const values: any[] = [academiaId];

      if (query.promocion_id !== undefined) {
        where.push("ps.promocion_id = ?");
        values.push(query.promocion_id);
      }

      if (query.sucursal_id !== undefined) {
        where.push("ps.sucursal_id = ?");
        values.push(query.sucursal_id);
      }

      values.push(query.limit);

      const [rows]: any = await db.query(
        `
        SELECT
          ps.id,
          ps.academia_id,
          ps.promocion_id,
          ps.sucursal_id,
          ps.created_at,

          p.nombre AS promocion_nombre,
          p.tipo_beneficio,
          p.valor,
          p.fecha_desde,
          p.fecha_hasta,
          p.estado_id AS promocion_estado_id,

          sr.nombre AS sucursal_nombre

        FROM promocion_sucursal ps

        INNER JOIN promociones_academia p
          ON p.id = ps.promocion_id
         AND p.academia_id = ps.academia_id

        INNER JOIN sucursales_real sr
          ON sr.id = ps.sucursal_id
         AND sr.academia_id = ps.academia_id

        WHERE ${where.join(" AND ")}

        ORDER BY
          p.nombre ASC,
          sr.nombre ASC,
          ps.id ASC

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
      if (handled) return handled;

      return reply.code(500).send({
        ok: false,
        message: "Error al listar relaciones promoción-sucursal",
      });
    }
  });

  /* =======================================================
     GET /:id
  ======================================================= */

  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
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
      const row = await getPromocionSucursal(academiaId, parsed.data.id);

      reply.header("Cache-Control", "no-store");

      if (!row) {
        return reply.code(404).send({
          ok: false,
          message: "Relación promoción-sucursal no encontrada",
        });
      }

      return reply.send({
        ok: true,
        item: normalize(row),
      });
    } catch (err: any) {
      const handled = handleScopeError(reply, err);
      if (handled) return handled;

      reply.header("Cache-Control", "no-store");

      return reply.code(500).send({
        ok: false,
        message: "Error al obtener relación promoción-sucursal",
      });
    }
  });

  /* =======================================================
     POST /
  ======================================================= */

  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academiaId = resolveAcademiaId(req);
      const body = CreateSchema.parse(req.body);

      await validatePromocion(academiaId, body.promocion_id);
      await validateSucursal(academiaId, body.sucursal_id);

      const duplicate = await existsRelation(academiaId, body.promocion_id, body.sucursal_id);

      if (duplicate) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La promoción ya está asociada a esta sucursal",
        });
      }

      const [result]: any = await db.query(
        `
        INSERT INTO promocion_sucursal
          (academia_id, promocion_id, sucursal_id)
        VALUES (?, ?, ?)
        `,
        [academiaId, body.promocion_id, body.sucursal_id]
      );

      const insertId = Number(result?.insertId);
      const row = await getPromocionSucursal(academiaId, insertId);

      reply.header("Cache-Control", "no-store");

      return reply.code(201).send({
        ok: true,
        id: insertId,

        item: row
          ? normalize(row)
          : {
              id: insertId,
              academia_id: academiaId,
              promocion_id: body.promocion_id,
              sucursal_id: body.sucursal_id,
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
          message: "La promoción ya está asociada a esta sucursal",
        });
      }

      if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
        return reply.code(409).send({
          ok: false,
          message: "La promoción o sucursal indicada no existe",
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
        message: "Error al asociar promoción con sucursal",
      });
    }
  });

  /* =======================================================
     PUT /:id
  ======================================================= */

  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
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

      const current = await getPromocionSucursal(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Relación promoción-sucursal no encontrada",
        });
      }

      const body = PutSchema.parse(req.body);

      const changed =
        body.promocion_id !== Number(current.promocion_id) || body.sucursal_id !== Number(current.sucursal_id);

      if (changed && (await relationHasCargos(academiaId, Number(current.promocion_id), Number(current.sucursal_id)))) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La relación promoción-sucursal ya fue utilizada en cargos y no puede modificarse",
        });
      }

      await validatePromocion(academiaId, body.promocion_id);
      await validateSucursal(academiaId, body.sucursal_id);

      const duplicate = await existsRelation(academiaId, body.promocion_id, body.sucursal_id, id);

      if (duplicate) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "Ya existe otra asociación entre esta promoción y esta sucursal",
        });
      }

      const [result]: any = await db.query(
        `
        UPDATE promocion_sucursal
        SET
          promocion_id = ?,
          sucursal_id = ?
        WHERE id = ?
          AND academia_id = ?
        LIMIT 1
        `,
        [body.promocion_id, body.sucursal_id, id, academiaId]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Relación promoción-sucursal no encontrada",
        });
      }

      const updated = await getPromocionSucursal(academiaId, id);

      return reply.send({
        ok: true,

        updated: updated
          ? normalize(updated)
          : {
              id,
              academia_id: academiaId,
              promocion_id: body.promocion_id,
              sucursal_id: body.sucursal_id,
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
          message: "Ya existe otra asociación entre esta promoción y esta sucursal",
        });
      }

      if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
        return reply.code(409).send({
          ok: false,
          message: "La promoción o sucursal indicada no existe",
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
        message: "Error al actualizar relación promoción-sucursal",
      });
    }
  });

  /* =======================================================
     PATCH /:id
  ======================================================= */

  app.patch("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
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

      const current = await getPromocionSucursal(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Relación promoción-sucursal no encontrada",
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
        promocion_id: body.promocion_id ?? Number(current.promocion_id),
        sucursal_id: body.sucursal_id ?? Number(current.sucursal_id),
      };

      const changed =
        merged.promocion_id !== Number(current.promocion_id) || merged.sucursal_id !== Number(current.sucursal_id);

      if (changed && (await relationHasCargos(academiaId, Number(current.promocion_id), Number(current.sucursal_id)))) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La relación promoción-sucursal ya fue utilizada en cargos y no puede modificarse",
        });
      }

      await validatePromocion(academiaId, merged.promocion_id);
      await validateSucursal(academiaId, merged.sucursal_id);

      const duplicate = await existsRelation(academiaId, merged.promocion_id, merged.sucursal_id, id);

      if (duplicate) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "Ya existe otra asociación entre esta promoción y esta sucursal",
        });
      }

      const [result]: any = await db.query(
        `
        UPDATE promocion_sucursal
        SET
          promocion_id = ?,
          sucursal_id = ?
        WHERE id = ?
          AND academia_id = ?
        LIMIT 1
        `,
        [merged.promocion_id, merged.sucursal_id, id, academiaId]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Relación promoción-sucursal no encontrada",
        });
      }

      const updated = await getPromocionSucursal(academiaId, id);

      return reply.send({
        ok: true,

        updated: updated
          ? normalize(updated)
          : {
              id,
              academia_id: academiaId,
              promocion_id: merged.promocion_id,
              sucursal_id: merged.sucursal_id,
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
          message: "Ya existe otra asociación entre esta promoción y esta sucursal",
        });
      }

      if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
        return reply.code(409).send({
          ok: false,
          message: "La promoción o sucursal indicada no existe",
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
        message: "Error al actualizar relación promoción-sucursal",
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

      return reply.code(400).send({
        ok: false,
        message: "ID inválido",
      });
    }

    try {
      const academiaId = resolveAcademiaId(req);
      const id = parsed.data.id;

      const current = await getPromocionSucursal(academiaId, id);

      if (!current) {
        reply.header("Cache-Control", "no-store");

        return reply.code(404).send({
          ok: false,
          message: "Relación promoción-sucursal no encontrada",
        });
      }

      if (await relationHasCargos(academiaId, Number(current.promocion_id), Number(current.sucursal_id))) {
        reply.header("Cache-Control", "no-store");

        return reply.code(409).send({
          ok: false,
          message: "La relación promoción-sucursal ya fue utilizada para generar cargos y no puede eliminarse",
        });
      }

      const [result]: any = await db.query(
        `
        DELETE FROM promocion_sucursal
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
          message: "Relación promoción-sucursal no encontrada",
        });
      }

      return reply.send({
        ok: true,
        deleted: id,
      });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      const handled = handleScopeError(reply, err);
      if (handled) return handled;

      if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar la relación porque está en uso",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar relación promoción-sucursal",
      });
    }
  });
}
