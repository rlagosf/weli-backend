// src/routers/ciudades.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * =========================================================
 * WELI - CIUDADES
 * =========================================================
 *
 * Catálogo territorial GLOBAL.
 *
 * Seguridad:
 * - READ: roles 1, 2 y 3.
 * - WRITE: solo Superadmin (rol 3).
 *
 * No usa getEffectiveAcademiaId():
 * ciudad pertenece al catálogo territorial global.
 * =========================================================
 */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const EstadoSchema = z.coerce.number().int().min(0).max(1);

const ListQuery = z.object({
  region_id: z.coerce.number().int().positive().optional(),
  estado_id: EstadoSchema.optional(),
  q: z.string().trim().min(1).max(120).optional(),
  limit: z.coerce.number().int().positive().max(1000).default(500),
  offset: z.coerce.number().int().nonnegative().default(0),
});

const CreateSchema = z
  .object({
    region_id: z.coerce.number().int().positive(),
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(120),
    estado_id: EstadoSchema.optional().default(1),
  })
  .strict();

const PutSchema = z
  .object({
    region_id: z.coerce.number().int().positive(),
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(120),
    estado_id: EstadoSchema,
  })
  .strict();

const PatchSchema = z
  .object({
    region_id: z.coerce.number().int().positive().optional(),
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(120).optional(),
    estado_id: EstadoSchema.optional(),
  })
  .strict();

function normalize(row: any) {
  return {
    id: Number(row.id),
    region_id: Number(row.region_id),
    region_nombre: row.region_nombre == null ? null : String(row.region_nombre),
    nombre: String(row.nombre ?? ""),
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

function normalizeName(value: string): string {
  return String(value ?? "")
    .trim()
    .replace(/\s+/g, " ");
}

async function validateRegion(regionId: number) {
  const [rows]: any = await db.query(
    `
      SELECT id
      FROM regiones
      WHERE id = ?
        AND estado_id = 1
      LIMIT 1
    `,
    [regionId]
  );

  if (!rows?.length) {
    throw Object.assign(new Error("La región no existe o se encuentra inactiva"), {
      statusCode: 400,
    });
  }
}

async function existsByNombreRegion(regionId: number, nombre: string, excludeId?: number) {
  const normalized = normalizeName(nombre);

  if (excludeId) {
    const [rows]: any = await db.query(
      `
        SELECT id
        FROM ciudades
        WHERE region_id = ?
          AND LOWER(TRIM(nombre)) = LOWER(?)
          AND id <> ?
        LIMIT 1
      `,
      [regionId, normalized, excludeId]
    );

    return Array.isArray(rows) && rows.length > 0;
  }

  const [rows]: any = await db.query(
    `
      SELECT id
      FROM ciudades
      WHERE region_id = ?
        AND LOWER(TRIM(nombre)) = LOWER(?)
      LIMIT 1
    `,
    [regionId, normalized]
  );

  return Array.isArray(rows) && rows.length > 0;
}

export default async function ciudades(app: FastifyInstance) {
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([3])];

  app.get("/health", { preHandler: canRead }, async (_req, reply) => {
    reply.header("Cache-Control", "no-store");

    return {
      module: "ciudades",
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
      const { region_id, estado_id, q, limit, offset } = ListQuery.parse((req as any).query ?? {});

      const where: string[] = [];
      const params: any[] = [];

      if (region_id !== undefined) {
        where.push("c.region_id = ?");
        params.push(region_id);
      }

      if (estado_id !== undefined) {
        where.push("c.estado_id = ?");
        params.push(estado_id);
      }

      if (q) {
        where.push("c.nombre LIKE ?");
        params.push(`%${q}%`);
      }

      const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

      const [rows]: any = await db.query(
        `
          SELECT
            c.id,
            c.region_id,
            r.nombre AS region_nombre,
            c.nombre,
            c.estado_id,
            c.created_at,
            c.updated_at
          FROM ciudades c
          INNER JOIN regiones r
            ON r.id = c.region_id
          ${whereSql}
          ORDER BY
            r.nombre ASC,
            c.nombre ASC,
            c.id ASC
          LIMIT ?
          OFFSET ?
        `,
        [...params, limit, offset]
      );

      const [countRows]: any = await db.query(
        `
          SELECT COUNT(*) AS total
          FROM ciudades c
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
        ciudades: normalized,
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
        message: "Error al listar ciudades",
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
            c.id,
            c.region_id,
            r.nombre AS region_nombre,
            c.nombre,
            c.estado_id,
            c.created_at,
            c.updated_at
          FROM ciudades c
          INNER JOIN regiones r
            ON r.id = c.region_id
          WHERE c.id = ?
          LIMIT 1
        `,
        [parsed.data.id]
      );

      reply.header("Cache-Control", "no-store");

      if (!rows?.length) {
        return reply.code(404).send({ ok: false, message: "Ciudad no encontrada" });
      }

      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al obtener ciudad",
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
      const nombre = normalizeName(body.nombre);

      await validateRegion(body.region_id);

      if (await existsByNombreRegion(body.region_id, nombre)) {
        reply.header("Cache-Control", "no-store");
        return reply.code(409).send({
          ok: false,
          message: "La ciudad ya existe en esta región",
        });
      }

      const [result]: any = await db.query(
        `
          INSERT INTO ciudades (
            region_id,
            nombre,
            estado_id
          )
          VALUES (?, ?, ?)
        `,
        [body.region_id, nombre, body.estado_id]
      );

      reply.header("Cache-Control", "no-store");

      return reply.code(201).send({
        ok: true,
        id: Number(result.insertId),
        item: {
          id: Number(result.insertId),
          region_id: Number(body.region_id),
          nombre,
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
          message: "La ciudad ya existe en esta región",
        });
      }

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al crear ciudad",
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
      const nombre = normalizeName(body.nombre);

      await validateRegion(body.region_id);

      if (await existsByNombreRegion(body.region_id, nombre, id)) {
        reply.header("Cache-Control", "no-store");
        return reply.code(409).send({
          ok: false,
          message: "La ciudad ya existe en esta región",
        });
      }

      const [result]: any = await db.query(
        `
          UPDATE ciudades
          SET
            region_id = ?,
            nombre = ?,
            estado_id = ?
          WHERE id = ?
        `,
        [body.region_id, nombre, body.estado_id, id]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "Ciudad no encontrada" });
      }

      return reply.send({
        ok: true,
        updated: {
          id,
          region_id: Number(body.region_id),
          nombre,
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
          message: "La ciudad ya existe en esta región",
        });
      }

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al actualizar ciudad",
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
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const [currentRows]: any = await db.query(
        `
          SELECT
            id,
            region_id,
            nombre,
            estado_id
          FROM ciudades
          WHERE id = ?
          LIMIT 1
        `,
        [id]
      );

      if (!currentRows?.length) {
        reply.header("Cache-Control", "no-store");
        return reply.code(404).send({ ok: false, message: "Ciudad no encontrada" });
      }

      const current = currentRows[0];

      const regionId = Number(body.region_id ?? current.region_id);
      const nombre = normalizeName(body.nombre ?? current.nombre);
      const estadoId = Number(body.estado_id ?? current.estado_id);

      await validateRegion(regionId);

      if (await existsByNombreRegion(regionId, nombre, id)) {
        reply.header("Cache-Control", "no-store");
        return reply.code(409).send({
          ok: false,
          message: "La ciudad ya existe en esta región",
        });
      }

      const [result]: any = await db.query(
        `
          UPDATE ciudades
          SET
            region_id = ?,
            nombre = ?,
            estado_id = ?
          WHERE id = ?
        `,
        [regionId, nombre, estadoId, id]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "Ciudad no encontrada" });
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
          message: "La ciudad ya existe en esta región",
        });
      }

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al actualizar ciudad",
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

      const [result]: any = await db.query("DELETE FROM ciudades WHERE id = ?", [id]);

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "Ciudad no encontrada" });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      if (err?.errno === 1451 || String(err?.code ?? "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar la ciudad porque posee relaciones ciudad-comuna asociadas.",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al eliminar ciudad",
        detail: err?.message,
      });
    }
  });
}
