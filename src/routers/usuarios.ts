// src/routers/usuarios.ts
import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { z } from "zod";
import * as argon2 from "@node-rs/argon2";
import { db } from "../db";

// ✅ Ajusta si tu path difiere
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: usuarios
 * Columnas:
 *  id, nombre_usuario, rut_usuario, email, password (hash argon2), rol_id, estado_id
 * Regla: uso EXCLUSIVO rol 1 (ADMIN) para TODO.
 */

// ───────── Schemas ─────────
const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const RutParam = z.object({
  rut_usuario: z.coerce.number().int().positive(),
});

const PageQuery = z.object({
  limit: z.coerce.number().int().positive().max(200).optional().default(50),
  offset: z.coerce.number().int().nonnegative().optional().default(0),
  q: z.string().trim().min(1).max(100).optional(),
});

const CreateSchema = z
  .object({
    nombre_usuario: z.string().trim().min(1, "nombre_usuario es obligatorio"),
    rut_usuario: z.union([z.coerce.number().int().positive(), z.string().regex(/^\d{6,10}$/, "rut_usuario inválido")]),
    email: z.string().trim().email("email inválido"),
    password: z.string().min(6, "password mínimo 6 caracteres"),
    rol_id: z.coerce.number().int().positive(),
    estado_id: z.coerce.number().int().positive(),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre_usuario: z.string().trim().min(1).optional(),
    rut_usuario: z
      .union([z.coerce.number().int().positive(), z.string().regex(/^\d{6,10}$/, "rut_usuario inválido")])
      .optional(),
    email: z.string().trim().email().optional(),
    password: z.string().min(6).optional(),
    rol_id: z.coerce.number().int().positive().optional(),
    estado_id: z.coerce.number().int().positive().optional(),
  })
  .strict();

// whitelist
const allowedKeys = new Set(["nombre_usuario", "rut_usuario", "email", "password", "rol_id", "estado_id"]);

function pickAllowed(body: Record<string, unknown>) {
  const out: Record<string, unknown> = {};
  for (const k in body) if (allowedKeys.has(k)) out[k] = (body as any)[k];
  return out;
}

function normalizeForDB(input: Record<string, unknown>) {
  const out: Record<string, any> = { ...input };

  if (typeof out.nombre_usuario === "string") out.nombre_usuario = out.nombre_usuario.trim();
  if (typeof out.email === "string") out.email = out.email.trim().toLowerCase();

  if (out.rut_usuario != null && out.rut_usuario !== "") {
    const rutN = Number(out.rut_usuario);
    out.rut_usuario = Number.isNaN(rutN) ? null : rutN;
  }

  if (out.rol_id != null) out.rol_id = Number(out.rol_id);
  if (out.estado_id != null) out.estado_id = Number(out.estado_id);

  // normaliza vacíos
  for (const k of Object.keys(out)) {
    if (out[k] === "") out[k] = null;
  }

  return out;
}

function noStore(reply: FastifyReply) {
  reply.header("Cache-Control", "no-store");
}

function duplicateFieldFromSqlMessage(msg?: string) {
  const s = String(msg || "").toLowerCase();
  if (s.includes("email")) return "email";
  if (s.includes("rut")) return "rut_usuario";
  if (s.includes("nombre_usuario")) return "nombre_usuario";
  return undefined;
}

export default async function usuarios(app: FastifyInstance) {
  // 🔐 Uso EXCLUSIVO rol 1
  const onlyRole1 = [requireAuth, requireRoles([1])];

  // ───────────────── Health ─────────────────
  app.get("/health", { preHandler: onlyRole1 }, async (_req, reply) => {
    noStore(reply);
    return {
      module: "usuarios",
      status: "ready",
      timestamp: new Date().toISOString(),
    };
  });

  // ───────────────── LIST ─────────────────
  app.get("/", { preHandler: onlyRole1 }, async (req: FastifyRequest, reply: FastifyReply) => {
    noStore(reply);

    const parsed = PageQuery.safeParse((req as any).query);
    const { limit, offset, q } = parsed.success ? parsed.data : { limit: 50, offset: 0, q: undefined };

    try {
      let sql = "SELECT id, nombre_usuario, rut_usuario, email, rol_id, estado_id FROM usuarios";
      const args: any[] = [];

      if (q) {
        sql += " WHERE nombre_usuario LIKE ? OR email LIKE ? OR CAST(rut_usuario AS CHAR) LIKE ?";
        const like = `%${q}%`;
        args.push(like, like, like);
      }

      sql += " ORDER BY nombre_usuario ASC, id ASC LIMIT ? OFFSET ?";
      args.push(limit, offset);

      const [rows]: any = await db.query(sql, args);

      reply.send({
        ok: true,
        items: rows ?? [],
        limit,
        offset,
        count: rows?.length ?? 0,
        filters: { q: q ?? null },
      });
    } catch (err: any) {
      reply.code(500).send({ ok: false, message: "Error al listar usuarios", detail: err?.message });
    }
  });

  // ⚠️ /rut/:rut_usuario ANTES de /:id

  // ───────────────── GET by rut ─────────────────
  app.get("/rut/:rut_usuario", { preHandler: onlyRole1 }, async (req: FastifyRequest, reply: FastifyReply) => {
    noStore(reply);

    const parsed = RutParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "RUT inválido" });

    const rut_usuario = parsed.data.rut_usuario;

    try {
      const [rows]: any = await db.query(
        "SELECT id, nombre_usuario, rut_usuario, email, rol_id, estado_id FROM usuarios WHERE rut_usuario = ? ORDER BY id DESC",
        [rut_usuario]
      );

      reply.send({ ok: true, items: rows ?? [] });
    } catch (err: any) {
      reply.code(500).send({ ok: false, message: "Error al buscar por RUT", detail: err?.message });
    }
  });

  // ───────────────── GET by id ─────────────────
  app.get("/:id", { preHandler: onlyRole1 }, async (req: FastifyRequest, reply: FastifyReply) => {
    noStore(reply);

    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsed.data.id;

    try {
      const [rows]: any = await db.query(
        "SELECT id, nombre_usuario, rut_usuario, email, rol_id, estado_id FROM usuarios WHERE id = ? LIMIT 1",
        [id]
      );

      if (!rows?.length) return reply.code(404).send({ ok: false, message: "No encontrado" });

      reply.send({ ok: true, item: rows[0] });
    } catch (err: any) {
      reply.code(500).send({ ok: false, message: "Error al obtener usuario", detail: err?.message });
    }
  });

  // ───────────────── CREATE ─────────────────
  app.post("/", { preHandler: onlyRole1 }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = CreateSchema.safeParse((req as any).body);
    if (!parsed.success) {
      const detail = parsed.error.issues.map((iss) => `${iss.path.join(".")}: ${iss.message}`).join("; ");
      return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
    }

    const data: any = normalizeForDB(pickAllowed(parsed.data));

    // defensa extra
    if (!data.nombre_usuario || !data.email || !data.password || !data.rut_usuario || !data.rol_id || !data.estado_id) {
      return reply.code(400).send({ ok: false, message: "Payload inválido (campos requeridos faltantes)" });
    }

    try {
      // Hash password
      data.password = await argon2.hash(String(data.password));

      const [result]: any = await db.query(
        "INSERT INTO usuarios (nombre_usuario, rut_usuario, email, password, rol_id, estado_id) VALUES (?, ?, ?, ?, ?, ?)",
        [data.nombre_usuario, data.rut_usuario, data.email, data.password, data.rol_id, data.estado_id]
      );

      reply.code(201).send({
        ok: true,
        id: result.insertId,
        nombre_usuario: data.nombre_usuario,
        rut_usuario: data.rut_usuario,
        email: data.email,
        rol_id: data.rol_id,
        estado_id: data.estado_id,
      });
    } catch (err: any) {
      if (err?.errno === 1062) {
        return reply.code(409).send({
          ok: false,
          message: "Usuario duplicado (email o RUT ya existe)",
          field: duplicateFieldFromSqlMessage(err?.sqlMessage),
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      if (err?.errno === 1452) {
        return reply.code(409).send({
          ok: false,
          message: "Violación de clave foránea (rol_id o estado_id inválido)",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      reply.code(500).send({ ok: false, message: "Error al crear usuario", detail: err?.message });
    }
  });

  // ───────────────── UPDATE (parcial) ─────────────────
  app.put("/:id", { preHandler: onlyRole1 }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pid = IdParam.safeParse((req as any).params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = pid.data.id;

    const parsed = UpdateSchema.safeParse((req as any).body);
    if (!parsed.success) {
      const detail = parsed.error.issues.map((iss) => `${iss.path.join(".")}: ${iss.message}`).join("; ");
      return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
    }

    const changes: any = normalizeForDB(pickAllowed(parsed.data));
    if (Object.keys(changes).length === 0) {
      return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
    }

    try {
      // hash si viene password
      if (typeof changes.password === "string") {
        changes.password = await argon2.hash(String(changes.password));
      }

      // UPDATE explícito (sin SET ?)
      const setClauses: string[] = [];
      const values: any[] = [];

      if (changes.nombre_usuario !== undefined) {
        setClauses.push("nombre_usuario = ?");
        values.push(changes.nombre_usuario);
      }
      if (changes.rut_usuario !== undefined) {
        setClauses.push("rut_usuario = ?");
        values.push(changes.rut_usuario);
      }
      if (changes.email !== undefined) {
        setClauses.push("email = ?");
        values.push(changes.email);
      }
      if (changes.password !== undefined) {
        setClauses.push("password = ?");
        values.push(changes.password);
      }
      if (changes.rol_id !== undefined) {
        setClauses.push("rol_id = ?");
        values.push(changes.rol_id);
      }
      if (changes.estado_id !== undefined) {
        setClauses.push("estado_id = ?");
        values.push(changes.estado_id);
      }

      if (setClauses.length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      values.push(id);

      const [result]: any = await db.query(`UPDATE usuarios SET ${setClauses.join(", ")} WHERE id = ?`, values);

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      // nunca devolvemos password
      const { password, ...safe } = changes;
      reply.send({ ok: true, updated: { id, ...safe } });
    } catch (err: any) {
      if (err?.errno === 1062) {
        return reply.code(409).send({
          ok: false,
          message: "Usuario duplicado (email o RUT ya existe)",
          field: duplicateFieldFromSqlMessage(err?.sqlMessage),
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      if (err?.errno === 1452) {
        return reply.code(409).send({
          ok: false,
          message: "Violación de clave foránea (rol_id o estado_id inválido)",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      reply.code(500).send({ ok: false, message: "Error al actualizar usuario", detail: err?.message });
    }
  });

  // ───────────────── DELETE ─────────────────
  app.delete("/:id", { preHandler: onlyRole1 }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsed.data.id;

    try {
      const [result]: any = await db.query("DELETE FROM usuarios WHERE id = ?", [id]);

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      if (err?.errno === 1451) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: hay registros vinculados a este usuario.",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      reply.code(500).send({ ok: false, message: "Error al eliminar usuario", detail: err?.message });
    }
  });
}
