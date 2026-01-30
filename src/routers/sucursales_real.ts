// src/routers/sucursalesReal.ts
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";

// ✅ Ajusta si tu path difiere
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: sucursales_real
 * Campos: id (PK), nombre (VARCHAR UNIQUE)
 */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres"),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres").optional(),
  })
  .strict();

const PageQuery = z.object({
  limit: z.coerce.number().int().positive().max(500).default(200),
  offset: z.coerce.number().int().nonnegative().default(0),
  q: z.string().trim().min(1).optional(),
});

const allowedKeys = new Set(["nombre"]);

function pickAllowed(body: Record<string, any>) {
  const out: Record<string, any> = {};
  for (const k in body) if (allowedKeys.has(k)) out[k] = body[k];
  return out;
}

function normalize(row: any) {
  return {
    id: Number(row.id),
    nombre: String(row.nombre ?? ""),
  };
}

export default async function sucursales_real(app: FastifyInstance) {
  // ✅ Regla de oro:
  // - READ: roles 1 y 2
  // - WRITE: solo rol 1
  const canRead = [requireAuth, requireRoles([1, 2])];
  const canWrite = [requireAuth, requireRoles([1])];

  // ─────────────────── HEALTH (READ) ───────────────────
  app.get("/health", { preHandler: canRead }, async (_req, reply) => {
    reply.header("Cache-Control", "no-store");
    return {
      module: "sucursales_real",
      status: "ready",
      timestamp: new Date().toISOString(),
    };
  });

  // ─────────────────── LISTADO (READ) ───────────────────
  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = PageQuery.safeParse((req as any).query);
    const { limit, offset, q } = parsed.success ? parsed.data : { limit: 200, offset: 0, q: undefined };

    try {
      let sql = "SELECT id, nombre FROM sucursales_real";
      const args: any[] = [];

      if (q) {
        sql += " WHERE nombre LIKE ?";
        args.push(`%${q}%`);
      }

      sql += " ORDER BY nombre ASC, id ASC LIMIT ? OFFSET ?";
      args.push(limit, offset);

      const [rows]: any = await db.query(sql, args);

      reply.header("Cache-Control", "no-store");
      return reply.send({
        ok: true,
        items: (rows ?? []).map(normalize),
        limit,
        offset,
        count: rows?.length ?? 0,
      });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al listar sucursales",
        detail: err?.message,
      });
    }
  });

  // ─────────────────── OBTENER POR ID (READ) ───────────────────
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsed.data.id;

    try {
      const [rows]: any = await db.query("SELECT id, nombre FROM sucursales_real WHERE id = ? LIMIT 1", [id]);

      reply.header("Cache-Control", "no-store");

      if (!rows?.length) return reply.code(404).send({ ok: false, message: "Sucursal no encontrada" });

      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al obtener sucursal",
        detail: err?.message,
      });
    }
  });

  // ─────────────────── CREAR (WRITE) ───────────────────
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const parsed = CreateSchema.parse((req as any).body);
      const data = pickAllowed(parsed);
      if (typeof data.nombre === "string") data.nombre = data.nombre.trim();

      const [result]: any = await db.query("INSERT INTO sucursales_real (nombre) VALUES (?)", [data.nombre]);

      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        ...data,
      });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: "Datos inválidos", detail });
      }

      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "Ya existe una sucursal con ese nombre" });
      }

      return reply.code(500).send({ ok: false, message: "Error al crear sucursal", detail: err?.message });
    }
  });

  // ─────────────────── ACTUALIZAR (WRITE) ───────────────────
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsed.data.id;

    try {
      const body = UpdateSchema.parse((req as any).body);
      const changes = pickAllowed(body);

      if (typeof changes.nombre === "string") changes.nombre = changes.nombre.trim();

      if (Object.keys(changes).length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      // más compatible que "SET ?" si te ha dado dramas en otros hosts
      const setClauses: string[] = [];
      const values: any[] = [];

      if (changes.nombre !== undefined) {
        setClauses.push("nombre = ?");
        values.push(changes.nombre);
      }

      values.push(id);

      const [result]: any = await db.query(
        `UPDATE sucursales_real SET ${setClauses.join(", ")} WHERE id = ?`,
        values
      );

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "Sucursal no encontrada" });
      }

      return reply.send({ ok: true, updated: { id, ...changes } });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: "Datos inválidos", detail });
      }

      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "Ya existe una sucursal con ese nombre" });
      }

      return reply.code(500).send({ ok: false, message: "Error al actualizar sucursal", detail: err?.message });
    }
  });

  // ─────────────────── ELIMINAR (WRITE) ───────────────────
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsed.data.id;

    try {
      const [result]: any = await db.query("DELETE FROM sucursales_real WHERE id = ?", [id]);

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "Sucursal no encontrada" });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      if (err?.errno === 1451) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: hay jugadores vinculados a esta sucursal",
        });
      }

      return reply.code(500).send({
        ok: false,
        message: "Error al eliminar sucursal",
        detail: err?.message,
      });
    }
  });
}
