import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/* =========================
   Schemas
========================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(2).max(120),
    deporte_id: z.coerce.number().int().positive(),
    estado_id: z.coerce.number().int().positive().optional(), // 1 activado, 2 desactivado
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z.string().trim().min(2).max(120).optional(),
    deporte_id: z.coerce.number().int().positive().optional(),
    estado_id: z.coerce.number().int().positive().optional(),
  })
  .strict();

const ListQuery = z.object({
  limit: z.coerce.number().int().positive().max(500).default(100),
  offset: z.coerce.number().int().nonnegative().default(0),
  q: z.string().trim().min(1).optional(),
  estado_id: z.coerce.number().int().positive().optional(),
  deporte_id: z.coerce.number().int().positive().optional(),
});

/* =========================
   Router (DEFAULT)
========================= */

export default async function academias(app: FastifyInstance) {
  // ✅ Solo SUPERADMIN (rol 3) puede usar TODO este router
  const onlySuper = [requireAuth, requireRoles([3])];

  // Health (rol 3)
  app.get("/health", { preHandler: onlySuper }, async () => ({
    module: "academias",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // GET /api/academias?limit&offset&q&estado_id&deporte_id  (rol 3)
  app.get("/", { preHandler: onlySuper }, async (req, reply) => {
    try {
      const { limit, offset, q, estado_id, deporte_id } = ListQuery.parse(
        (req as any).query
      );

      const where: string[] = [];
      const params: any[] = [];

      if (q) {
        where.push("a.nombre LIKE ?");
        params.push(`%${q}%`);
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

      // ✅ JOIN deportes + estado_academia para entregar NOMBRES (no IDs feos)
      const [rows] = await db.query(
        `
        SELECT
          a.id,
          a.nombre,
          a.deporte_id,
          d.nombre AS deporte_nombre,
          a.estado_id,
          ea.nombre AS estado_nombre,
          a.created_at,
          a.updated_at
        FROM academias a
        JOIN deportes d ON d.id = a.deporte_id
        JOIN estado_academia ea ON ea.id = a.estado_id
        ${whereSql}
        ORDER BY a.id DESC
        LIMIT ? OFFSET ?
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

      const total = Array.isArray(countRows)
        ? (countRows as any)[0]?.total ?? 0
        : 0;

      return reply.send({ ok: true, total, limit, offset, data: rows });
    } catch (error: any) {
      const msg = error?.message ?? "BAD_REQUEST";
      return reply.code(400).send({ ok: false, message: msg });
    }
  });

  // GET /api/academias/:id  (rol 3)
  app.get("/:id", { preHandler: onlySuper }, async (req, reply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    const { id } = parsed.data;

    try {
      const [rows]: any = await db.query(
        `
        SELECT
          a.id,
          a.nombre,
          a.deporte_id,
          d.nombre AS deporte_nombre,
          a.estado_id,
          ea.nombre AS estado_nombre,
          a.created_at,
          a.updated_at
        FROM academias a
        JOIN deportes d ON d.id = a.deporte_id
        JOIN estado_academia ea ON ea.id = a.estado_id
        WHERE a.id = ?
        LIMIT 1
        `,
        [id]
      );

      if (!rows?.length) {
        return reply.code(404).send({ ok: false, message: "Academia no encontrada" });
      }

      return reply.send({ ok: true, item: rows[0] });
    } catch {
      return reply.code(500).send({ ok: false, message: "Error interno" });
    }
  });

  // POST /api/academias  (rol 3)
  app.post("/", { preHandler: onlySuper }, async (req, reply) => {
    try {
      const body = CreateSchema.parse(req.body);

      const nombre = body.nombre.trim();
      const deporte_id = body.deporte_id;
      const estado_id = body.estado_id ?? 1;

      const [result]: any = await db.query(
        `
        INSERT INTO academias (nombre, deporte_id, estado_id)
        VALUES (?, ?, ?)
        `,
        [nombre, deporte_id, estado_id]
      );

      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        nombre,
      });
    } catch (error: any) {
      const msg =
        error?.code === "ER_DUP_ENTRY"
          ? "Ya existe una academia con ese nombre"
          : error?.message ?? "BAD_REQUEST";

      return reply.code(error?.code === "ER_DUP_ENTRY" ? 409 : 400).send({
        ok: false,
        message: msg,
      });
    }
  });

  // PUT /api/academias/:id  (rol 3)
  app.put("/:id", { preHandler: onlySuper }, async (req, reply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    const { id } = parsed.data;

    try {
      const body = UpdateSchema.parse(req.body);

      const sets: string[] = [];
      const params: any[] = [];

      if (body.nombre !== undefined) {
        sets.push("nombre = ?");
        params.push(body.nombre.trim());
      }
      if (body.deporte_id !== undefined) {
        sets.push("deporte_id = ?");
        params.push(body.deporte_id);
      }
      if (body.estado_id !== undefined) {
        sets.push("estado_id = ?");
        params.push(body.estado_id);
      }

      if (!sets.length) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      params.push(id);

      const [result]: any = await db.query(
        `
        UPDATE academias
        SET ${sets.join(", ")}
        WHERE id = ?
        `,
        params
      );

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "Academia no encontrada" });
      }

      return reply.send({ ok: true, updated: id });
    } catch (error: any) {
      const msg =
        error?.code === "ER_DUP_ENTRY"
          ? "Ya existe una academia con ese nombre"
          : error?.message ?? "BAD_REQUEST";

      return reply.code(error?.code === "ER_DUP_ENTRY" ? 409 : 400).send({
        ok: false,
        message: msg,
      });
    }
  });

  // DELETE /api/academias/:id  (rol 3)
  app.delete("/:id", { preHandler: onlySuper }, async (req, reply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    const { id } = parsed.data;

    try {
      const [result]: any = await db.query(`DELETE FROM academias WHERE id = ?`, [id]);

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "Academia no encontrada" });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (error: any) {
      const msg =
        error?.code === "ER_ROW_IS_REFERENCED_2"
          ? "No se puede eliminar: está siendo usada por datos del sistema"
          : error?.message ?? "SERVER_ERROR";

      return reply.code(500).send({ ok: false, message: msg });
    }
  });
}
