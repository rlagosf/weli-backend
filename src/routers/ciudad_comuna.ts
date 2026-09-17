// src/routers/ciudad_comuna.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * =========================================================
 * WELI - CIUDAD_COMUNA
 * =========================================================
 *
 * Catálogo territorial GLOBAL.
 *
 * Relaciona ciudades con comunas válidas.
 *
 * Seguridad:
 * - READ: roles 1, 2 y 3.
 * - WRITE: solo Superadmin (rol 3).
 *
 * No usa getEffectiveAcademiaId():
 * la relación ciudad-comuna es global y no pertenece a un tenant.
 * =========================================================
 */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const EstadoSchema = z.coerce.number().int().min(0).max(1);

const ListQuery = z.object({
  ciudad_id: z.coerce.number().int().positive().optional(),
  comuna_id: z.coerce.number().int().positive().optional(),
  region_id: z.coerce.number().int().positive().optional(),
  estado_id: EstadoSchema.optional(),
  limit: z.coerce.number().int().positive().max(2000).default(1000),
  offset: z.coerce.number().int().nonnegative().default(0),
});

const CreateSchema = z
  .object({
    ciudad_id: z.coerce.number().int().positive(),
    comuna_id: z.coerce.number().int().positive(),
    estado_id: EstadoSchema.optional().default(1),
  })
  .strict();

const PutSchema = z
  .object({
    ciudad_id: z.coerce.number().int().positive(),
    comuna_id: z.coerce.number().int().positive(),
    estado_id: EstadoSchema,
  })
  .strict();

const PatchSchema = z
  .object({
    ciudad_id: z.coerce.number().int().positive().optional(),
    comuna_id: z.coerce.number().int().positive().optional(),
    estado_id: EstadoSchema.optional(),
  })
  .strict();

function normalize(row: any) {
  return {
    id: Number(row.id),
    ciudad_id: Number(row.ciudad_id),
    ciudad_nombre: row.ciudad_nombre == null ? null : String(row.ciudad_nombre),
    comuna_id: Number(row.comuna_id),
    comuna_nombre: row.comuna_nombre == null ? null : String(row.comuna_nombre),
    region_id: Number(row.region_id),
    region_nombre: row.region_nombre == null ? null : String(row.region_nombre),
    estado_id: Number(row.estado_id ?? 0),
    created_at: row.created_at ?? null,
    updated_at: row.updated_at ?? null,
  };
}

function zodDetail(err: ZodError) {
  return err.issues.map((i) => `${i.path.join(".") || "field"}: ${i.message}`).join("; ");
}

function errorCode(err: any): number {
  if (err?.statusCode && Number.isFinite(Number(err.statusCode))) {
    return Number(err.statusCode);
  }

  return 500;
}

async function getCiudad(ciudadId: number) {
  const [rows]: any = await db.query(
    `
      SELECT
        c.id,
        c.region_id,
        c.estado_id
      FROM ciudades c
      WHERE c.id = ?
      LIMIT 1
    `,
    [ciudadId]
  );

  if (!rows?.length) {
    throw Object.assign(new Error("La ciudad no existe"), {
      statusCode: 400,
    });
  }

  if (Number(rows[0].estado_id) !== 1) {
    throw Object.assign(new Error("La ciudad se encuentra inactiva"), {
      statusCode: 400,
    });
  }

  return rows[0];
}

async function getComuna(comunaId: number) {
  const [rows]: any = await db.query(
    `
      SELECT
        id,
        region_id
      FROM comunas
      WHERE id = ?
      LIMIT 1
    `,
    [comunaId]
  );

  if (!rows?.length) {
    throw Object.assign(new Error("La comuna no existe"), {
      statusCode: 400,
    });
  }

  return rows[0];
}

async function validateTerritorialRelation(ciudadId: number, comunaId: number) {
  const [ciudad, comuna] = await Promise.all([getCiudad(ciudadId), getComuna(comunaId)]);

  const ciudadRegionId = Number(ciudad.region_id);
  const comunaRegionId = Number(comuna.region_id);

  if (ciudadRegionId !== comunaRegionId) {
    throw Object.assign(new Error("La ciudad y la comuna deben pertenecer a la misma región"), {
      statusCode: 400,
    });
  }

  return ciudadRegionId;
}

async function existsPair(ciudadId: number, comunaId: number, excludeId?: number) {
  if (excludeId) {
    const [rows]: any = await db.query(
      `
        SELECT id
        FROM ciudad_comuna
        WHERE ciudad_id = ?
          AND comuna_id = ?
          AND id <> ?
        LIMIT 1
      `,
      [ciudadId, comunaId, excludeId]
    );

    return Array.isArray(rows) && rows.length > 0;
  }

  const [rows]: any = await db.query(
    `
      SELECT id
      FROM ciudad_comuna
      WHERE ciudad_id = ?
        AND comuna_id = ?
      LIMIT 1
    `,
    [ciudadId, comunaId]
  );

  return Array.isArray(rows) && rows.length > 0;
}

export default async function ciudadComuna(app: FastifyInstance) {
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([3])];

  app.get("/health", { preHandler: canRead }, async (_req, reply) => {
    reply.header("Cache-Control", "no-store");

    return {
      module: "ciudad-comuna",
      scope: "global",
      status: "ready",
      timestamp: new Date().toISOString(),
    };
  });

  /* =======================================================
     GET /
  ======================================================= */

  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const { ciudad_id, comuna_id, region_id, estado_id, limit, offset } = ListQuery.parse((req as any).query ?? {});

      const where: string[] = [];
      const params: any[] = [];

      if (ciudad_id !== undefined) {
        where.push("cc.ciudad_id = ?");
        params.push(ciudad_id);
      }

      if (comuna_id !== undefined) {
        where.push("cc.comuna_id = ?");
        params.push(comuna_id);
      }

      if (region_id !== undefined) {
        where.push("ci.region_id = ?");
        params.push(region_id);
      }

      if (estado_id !== undefined) {
        where.push("cc.estado_id = ?");
        params.push(estado_id);
      }

      const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

      const [rows]: any = await db.query(
        `
          SELECT
            cc.id,
            cc.ciudad_id,
            ci.nombre AS ciudad_nombre,
            cc.comuna_id,
            co.nombre AS comuna_nombre,
            ci.region_id,
            r.nombre AS region_nombre,
            cc.estado_id,
            cc.created_at,
            cc.updated_at
          FROM ciudad_comuna cc
          INNER JOIN ciudades ci
            ON ci.id = cc.ciudad_id
          INNER JOIN comunas co
            ON co.id = cc.comuna_id
          INNER JOIN regiones r
            ON r.id = ci.region_id
          ${whereSql}
          ORDER BY
            r.nombre ASC,
            ci.nombre ASC,
            co.nombre ASC,
            cc.id ASC
          LIMIT ?
          OFFSET ?
        `,
        [...params, limit, offset]
      );

      const [countRows]: any = await db.query(
        `
          SELECT COUNT(*) AS total
          FROM ciudad_comuna cc
          INNER JOIN ciudades ci
            ON ci.id = cc.ciudad_id
          ${whereSql}
        `,
        params
      );

      reply.header("Cache-Control", "no-store");

      const normalized = (rows ?? []).map(normalize);

      return reply.send({
        ok: true,
        count: normalized.length,
        total: Number(countRows?.[0]?.total ?? 0),
        limit,
        offset,
        items: normalized,
        ciudad_comuna: normalized,
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

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al listar relaciones ciudad-comuna",
        detail: err?.message,
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
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const [rows]: any = await db.query(
        `
          SELECT
            cc.id,
            cc.ciudad_id,
            ci.nombre AS ciudad_nombre,
            cc.comuna_id,
            co.nombre AS comuna_nombre,
            ci.region_id,
            r.nombre AS region_nombre,
            cc.estado_id,
            cc.created_at,
            cc.updated_at
          FROM ciudad_comuna cc
          INNER JOIN ciudades ci
            ON ci.id = cc.ciudad_id
          INNER JOIN comunas co
            ON co.id = cc.comuna_id
          INNER JOIN regiones r
            ON r.id = ci.region_id
          WHERE cc.id = ?
          LIMIT 1
        `,
        [parsed.data.id]
      );

      reply.header("Cache-Control", "no-store");

      if (!rows?.length) {
        return reply.code(404).send({
          ok: false,
          message: "Relación ciudad-comuna no encontrada",
        });
      }

      return reply.send({
        ok: true,
        item: normalize(rows[0]),
      });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al obtener relación ciudad-comuna",
        detail: err?.message,
      });
    }
  });

  /* =======================================================
     POST /
  ======================================================= */

  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const body = CreateSchema.parse(req.body);

      await validateTerritorialRelation(body.ciudad_id, body.comuna_id);

      if (await existsPair(body.ciudad_id, body.comuna_id)) {
        reply.header("Cache-Control", "no-store");
        return reply.code(409).send({
          ok: false,
          message: "La relación entre ciudad y comuna ya existe",
        });
      }

      const [result]: any = await db.query(
        `
          INSERT INTO ciudad_comuna (
            ciudad_id,
            comuna_id,
            estado_id
          )
          VALUES (?, ?, ?)
        `,
        [body.ciudad_id, body.comuna_id, body.estado_id]
      );

      reply.header("Cache-Control", "no-store");

      return reply.code(201).send({
        ok: true,
        id: Number(result.insertId),
        item: {
          id: Number(result.insertId),
          ciudad_id: Number(body.ciudad_id),
          comuna_id: Number(body.comuna_id),
          estado_id: Number(body.estado_id),
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

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({
          ok: false,
          message: "La relación entre ciudad y comuna ya existe",
        });
      }

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al crear relación ciudad-comuna",
        detail: err?.message,
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
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const id = parsed.data.id;
      const body = PutSchema.parse(req.body);

      await validateTerritorialRelation(body.ciudad_id, body.comuna_id);

      if (await existsPair(body.ciudad_id, body.comuna_id, id)) {
        reply.header("Cache-Control", "no-store");
        return reply.code(409).send({
          ok: false,
          message: "La relación entre ciudad y comuna ya existe",
        });
      }

      const [result]: any = await db.query(
        `
          UPDATE ciudad_comuna
          SET
            ciudad_id = ?,
            comuna_id = ?,
            estado_id = ?
          WHERE id = ?
        `,
        [body.ciudad_id, body.comuna_id, body.estado_id, id]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Relación ciudad-comuna no encontrada",
        });
      }

      return reply.send({
        ok: true,
        updated: {
          id,
          ciudad_id: Number(body.ciudad_id),
          comuna_id: Number(body.comuna_id),
          estado_id: Number(body.estado_id),
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

      if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
        return reply.code(409).send({
          ok: false,
          message: "La relación entre ciudad y comuna ya existe",
        });
      }

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al actualizar relación ciudad-comuna",
        detail: err?.message,
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
      return reply.code(400).send({ ok: false, message: "ID inválido" });
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

      const [currentRows]: any = await db.query(
        `
          SELECT
            id,
            ciudad_id,
            comuna_id,
            estado_id
          FROM ciudad_comuna
          WHERE id = ?
          LIMIT 1
        `,
        [id]
      );

      if (!currentRows?.length) {
        reply.header("Cache-Control", "no-store");
        return reply.code(404).send({
          ok: false,
          message: "Relación ciudad-comuna no encontrada",
        });
      }

      const current = currentRows[0];

      const ciudadId = Number(body.ciudad_id ?? current.ciudad_id);
      const comunaId = Number(body.comuna_id ?? current.comuna_id);
      const estadoId = Number(body.estado_id ?? current.estado_id);

      await validateTerritorialRelation(ciudadId, comunaId);

      if (await existsPair(ciudadId, comunaId, id)) {
        reply.header("Cache-Control", "no-store");
        return reply.code(409).send({
          ok: false,
          message: "La relación entre ciudad y comuna ya existe",
        });
      }

      const [result]: any = await db.query(
        `
          UPDATE ciudad_comuna
          SET
            ciudad_id = ?,
            comuna_id = ?,
            estado_id = ?
          WHERE id = ?
        `,
        [ciudadId, comunaId, estadoId, id]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Relación ciudad-comuna no encontrada",
        });
      }

      return reply.send({ ok: true, updated: id });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

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
          message: "La relación entre ciudad y comuna ya existe",
        });
      }

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al actualizar relación ciudad-comuna",
        detail: err?.message,
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
      const id = parsed.data.id;

      const [result]: any = await db.query(
        `
          DELETE FROM ciudad_comuna
          WHERE id = ?
        `,
        [id]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({
          ok: false,
          message: "Relación ciudad-comuna no encontrada",
        });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      if (err?.errno === 1451 || String(err?.code ?? "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar la relación ciudad-comuna porque está siendo utilizada por una academia.",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al eliminar relación ciudad-comuna",
        detail: err?.message,
      });
    }
  });
}
