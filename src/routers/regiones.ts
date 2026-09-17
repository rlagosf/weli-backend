// src/routers/regiones.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * =========================================================
 * WELI - REGIONES
 * =========================================================
 *
 * Catálogo territorial GLOBAL.
 *
 * Seguridad:
 * - READ: roles 1, 2 y 3.
 * - WRITE: solo Superadmin (rol 3).
 *
 * IMPORTANTE:
 * Este router NO usa getEffectiveAcademiaId().
 * Regiones no pertenecen a una academia; son catálogo global.
 * Exigir x-academia-id impediría, entre otras cosas, crear una
 * academia nueva antes de que exista un tenant seleccionado.
 * =========================================================
 */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const EstadoSchema = z.coerce.number().int().min(0).max(1);

const ListQuery = z.object({
  estado_id: EstadoSchema.optional(),
  q: z.string().trim().min(1).max(100).optional(),
  limit: z.coerce.number().int().positive().max(500).default(200),
  offset: z.coerce.number().int().nonnegative().default(0),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(100),
    estado_id: EstadoSchema.optional().default(1),
  })
  .strict();

const PutSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(100),
    estado_id: EstadoSchema,
  })
  .strict();

const PatchSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(100).optional(),
    estado_id: EstadoSchema.optional(),
  })
  .strict();

function normalize(row: any) {
  return {
    id: Number(row.id),
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

async function existsByNombre(nombre: string, excludeId?: number) {
  const normalized = normalizeName(nombre);

  if (excludeId) {
    const [rows]: any = await db.query(
      `
        SELECT id
        FROM regiones
        WHERE LOWER(TRIM(nombre)) = LOWER(?)
          AND id <> ?
        LIMIT 1
      `,
      [normalized, excludeId]
    );

    return Array.isArray(rows) && rows.length > 0;
  }

  const [rows]: any = await db.query(
    `
      SELECT id
      FROM regiones
      WHERE LOWER(TRIM(nombre)) = LOWER(?)
      LIMIT 1
    `,
    [normalized]
  );

  return Array.isArray(rows) && rows.length > 0;
}

export default async function regiones(app: FastifyInstance) {
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([3])];

  /* =======================================================
     HEALTH
  ======================================================= */

  app.get("/health", { preHandler: canRead }, async (_req, reply) => {
    reply.header("Cache-Control", "no-store");

    return {
      module: "regiones",
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
      const { estado_id, q, limit, offset } = ListQuery.parse((req as any).query ?? {});

      const where: string[] = [];
      const params: any[] = [];

      if (estado_id !== undefined) {
        where.push("estado_id = ?");
        params.push(estado_id);
      }

      if (q) {
        where.push("nombre LIKE ?");
        params.push(`%${q}%`);
      }

      const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

      const [rows]: any = await db.query(
        `
          SELECT
            id,
            nombre,
            estado_id,
            created_at,
            updated_at
          FROM regiones
          ${whereSql}
          ORDER BY nombre ASC, id ASC
          LIMIT ?
          OFFSET ?
        `,
        [...params, limit, offset]
      );

      const [countRows]: any = await db.query(
        `
          SELECT COUNT(*) AS total
          FROM regiones
          ${whereSql}
        `,
        params
      );

      reply.header("Cache-Control", "no-store");

      return reply.send({
        ok: true,
        count: rows?.length ?? 0,
        total: Number(countRows?.[0]?.total ?? 0),
        limit,
        offset,
        items: (rows ?? []).map(normalize),
        regiones: (rows ?? []).map(normalize),
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
        message: "Error al listar regiones",
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
            id,
            nombre,
            estado_id,
            created_at,
            updated_at
          FROM regiones
          WHERE id = ?
          LIMIT 1
        `,
        [parsed.data.id]
      );

      reply.header("Cache-Control", "no-store");

      if (!rows?.length) {
        return reply.code(404).send({ ok: false, message: "Región no encontrada" });
      }

      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al obtener región",
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

      if (await existsByNombre(nombre)) {
        reply.header("Cache-Control", "no-store");
        return reply.code(409).send({ ok: false, message: "La región ya existe" });
      }

      const [result]: any = await db.query(
        `
          INSERT INTO regiones (
            nombre,
            estado_id
          )
          VALUES (?, ?)
        `,
        [nombre, body.estado_id]
      );

      reply.header("Cache-Control", "no-store");

      return reply.code(201).send({
        ok: true,
        id: Number(result.insertId),
        item: {
          id: Number(result.insertId),
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
        return reply.code(409).send({ ok: false, message: "La región ya existe" });
      }

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al crear región",
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
      const body = PutSchema.parse(req.body);
      const id = parsed.data.id;
      const nombre = normalizeName(body.nombre);

      if (await existsByNombre(nombre, id)) {
        reply.header("Cache-Control", "no-store");
        return reply.code(409).send({ ok: false, message: "La región ya existe" });
      }

      const [result]: any = await db.query(
        `
          UPDATE regiones
          SET
            nombre = ?,
            estado_id = ?
          WHERE id = ?
        `,
        [nombre, body.estado_id, id]
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "Región no encontrada" });
      }

      return reply.send({
        ok: true,
        updated: {
          id,
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
        return reply.code(409).send({ ok: false, message: "La región ya existe" });
      }

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al actualizar región",
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
      const body = PatchSchema.parse(req.body);

      if (Object.keys(body).length === 0) {
        reply.header("Cache-Control", "no-store");
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const id = parsed.data.id;
      const sets: string[] = [];
      const values: any[] = [];

      if (body.nombre !== undefined) {
        const nombre = normalizeName(body.nombre);

        if (await existsByNombre(nombre, id)) {
          reply.header("Cache-Control", "no-store");
          return reply.code(409).send({ ok: false, message: "La región ya existe" });
        }

        sets.push("nombre = ?");
        values.push(nombre);
      }

      if (body.estado_id !== undefined) {
        sets.push("estado_id = ?");
        values.push(body.estado_id);
      }

      values.push(id);

      const [result]: any = await db.query(
        `
          UPDATE regiones
          SET ${sets.join(", ")}
          WHERE id = ?
        `,
        values
      );

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "Región no encontrada" });
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
        return reply.code(409).send({ ok: false, message: "La región ya existe" });
      }

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al actualizar región",
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

      const [result]: any = await db.query("DELETE FROM regiones WHERE id = ?", [id]);

      reply.header("Cache-Control", "no-store");

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "Región no encontrada" });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      reply.header("Cache-Control", "no-store");

      if (err?.errno === 1451 || String(err?.code ?? "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar la región porque posee comunas o ciudades asociadas.",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(errorCode(err)).send({
        ok: false,
        message: "Error al eliminar región",
        detail: err?.message,
      });
    }
  });
}
