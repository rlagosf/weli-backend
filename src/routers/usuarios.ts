import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { z } from "zod";
import * as argon2 from "@node-rs/argon2";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: usuarios
 * Columnas:
 *  id, academia_id, nombre_usuario, rut_usuario, email,
 *  password (hash argon2), rol_id, estado_id
 *
 * Reglas WELI:
 *  - READ: roles 1 y 3
 *  - WRITE: roles 1 y 3
 *  - Scope academia:
 *      - rol 1: solo su academia_id (y al crear SIEMPRE se fuerza a su academia)
 *      - rol 3: bypass (puede ver/crear/editar en cualquier academia)
 */

/* ──────────────────────────────
   Auth helpers (academy scope)
──────────────────────────────── */
function getAuth(req: any) {
  return (req as any).auth as
    | { type: "user"; user_id?: number; rol_id?: number; academia_id?: number }
    | { type: "apoderado"; rut: string; apoderado_id?: number }
    | undefined;
}

function isSuper(req: any) {
  const a = getAuth(req);
  return a?.type === "user" && Number(a.rol_id) === 3;
}

function getAcademiaIdOr403(req: any, reply: FastifyReply): number | null {
  const a = getAuth(req);
  if (!a || a.type !== "user") {
    reply.code(403).send({ ok: false, message: "FORBIDDEN" });
    return 0 as any;
  }
  if (Number(a.rol_id) === 3) return null; // superadmin bypass

  const academia_id = Number(a.academia_id ?? 0);
  if (!Number.isFinite(academia_id) || academia_id <= 0) {
    reply.code(403).send({ ok: false, message: "ACADEMIA_REQUIRED" });
    return 0 as any;
  }
  return academia_id;
}

async function assertUserInAcademiaOr404(id: number, academia_id: number | null, reply: FastifyReply) {
  if (!academia_id) return true; // super bypass

  const [rows]: any = await db.query(
    `SELECT id FROM usuarios WHERE id = ? AND academia_id = ? LIMIT 1`,
    [id, academia_id]
  );

  if (!rows?.length) {
    // 404 para no filtrar multi-tenant
    reply.code(404).send({ ok: false, message: "No encontrado" });
    return false;
  }
  return true;
}

function noStore(reply: FastifyReply) {
  reply.header("Cache-Control", "no-store");
}

function duplicateFieldFromSqlMessage(msg?: string) {
  const s = String(msg || "").toLowerCase();
  if (s.includes("email")) return "email";
  if (s.includes("rut")) return "rut_usuario";
  if (s.includes("nombre_usuario")) return "nombre_usuario";
  if (s.includes("academia")) return "academia_id";
  return undefined;
}

/* ──────────────────────────────
   Schemas
──────────────────────────────── */
const IdParam = z.object({ id: z.coerce.number().int().positive() });

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
    // academia_id: requerido solo si crea superadmin (rol 3). Para rol 1 se ignora y se fuerza.
    academia_id: z.coerce.number().int().positive().optional(),
    nombre_usuario: z.string().trim().min(1, "nombre_usuario es obligatorio"),
    rut_usuario: z.union([
      z.coerce.number().int().positive(),
      z.string().regex(/^\d{6,10}$/, "rut_usuario inválido"),
    ]),
    email: z.string().trim().email("email inválido"),
    password: z.string().min(6, "password mínimo 6 caracteres"),
    rol_id: z.coerce.number().int().positive(),
    estado_id: z.coerce.number().int().positive(),
  })
  .strict();

const UpdateSchema = z
  .object({
    // solo rol 3 debería poder mover academia_id; rol 1 NO.
    academia_id: z.coerce.number().int().positive().optional(),
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
const allowedKeys = new Set([
  "academia_id",
  "nombre_usuario",
  "rut_usuario",
  "email",
  "password",
  "rol_id",
  "estado_id",
]);

function pickAllowed(body: Record<string, unknown>) {
  const out: Record<string, unknown> = {};
  for (const k in body) if (allowedKeys.has(k)) out[k] = (body as any)[k];
  return out;
}

function normalizeForDB(input: Record<string, unknown>) {
  const out: Record<string, any> = { ...input };

  if (out.academia_id != null) out.academia_id = Number(out.academia_id);

  if (typeof out.nombre_usuario === "string") out.nombre_usuario = out.nombre_usuario.trim();
  if (typeof out.email === "string") out.email = out.email.trim().toLowerCase();

  if (out.rut_usuario != null && out.rut_usuario !== "") {
    const rutN = Number(out.rut_usuario);
    out.rut_usuario = Number.isNaN(rutN) ? null : rutN;
  }

  if (out.rol_id != null) out.rol_id = Number(out.rol_id);
  if (out.estado_id != null) out.estado_id = Number(out.estado_id);

  for (const k of Object.keys(out)) {
    if (out[k] === "") out[k] = null;
  }

  return out;
}

/* ──────────────────────────────
   Router
──────────────────────────────── */
export default async function usuarios(app: FastifyInstance) {
  // 🔐 READ/WRITE: roles 1 y 3
  const canRead = [requireAuth, requireRoles([1, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  // ───────────────── Health (READ) ─────────────────
  app.get("/health", { preHandler: canRead }, async (_req, reply) => {
    noStore(reply);
    return { module: "usuarios", status: "ready", timestamp: new Date().toISOString() };
  });

  // ───────────────── LIST (READ) ─────────────────
  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    noStore(reply);

    const parsed = PageQuery.safeParse((req as any).query);
    const { limit, offset, q } = parsed.success ? parsed.data : { limit: 50, offset: 0, q: undefined };

    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;

    try {
      let sql =
        "SELECT id, academia_id, nombre_usuario, rut_usuario, email, rol_id, estado_id FROM usuarios WHERE 1=1";
      const args: any[] = [];

      if (academia_id) {
        sql += " AND academia_id = ?";
        args.push(academia_id);
      }

      if (q) {
        sql += " AND (nombre_usuario LIKE ? OR email LIKE ? OR CAST(rut_usuario AS CHAR) LIKE ?)";
        const like = `%${q.replace(/[%_]/g, "\\$&")}%`;
        args.push(like, like, like);
      }

      sql += " ORDER BY nombre_usuario ASC, id ASC LIMIT ? OFFSET ?";
      args.push(limit, offset);

      const [rows]: any = await db.query(sql, args);

      return reply.send({
        ok: true,
        items: rows ?? [],
        limit,
        offset,
        count: rows?.length ?? 0,
        filters: { q: q ?? null },
      });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al listar usuarios", detail: err?.message });
    }
  });

  // ⚠️ /rut/:rut_usuario ANTES de /:id

  // ───────────────── GET by rut (READ) ─────────────────
  app.get("/rut/:rut_usuario", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    noStore(reply);

    const parsed = RutParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "RUT inválido" });

    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;

    try {
      let sql =
        "SELECT id, academia_id, nombre_usuario, rut_usuario, email, rol_id, estado_id FROM usuarios WHERE rut_usuario = ?";
      const args: any[] = [parsed.data.rut_usuario];

      if (academia_id) {
        sql += " AND academia_id = ?";
        args.push(academia_id);
      }

      sql += " ORDER BY id DESC";

      const [rows]: any = await db.query(sql, args);
      return reply.send({ ok: true, items: rows ?? [] });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al buscar por RUT", detail: err?.message });
    }
  });

  // ───────────────── GET by id (READ) ─────────────────
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    noStore(reply);

    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;

    try {
      let sql =
        "SELECT id, academia_id, nombre_usuario, rut_usuario, email, rol_id, estado_id FROM usuarios WHERE id = ? ";
      const args: any[] = [parsed.data.id];

      if (academia_id) {
        sql += " AND academia_id = ?";
        args.push(academia_id);
      }

      sql += " LIMIT 1";

      const [rows]: any = await db.query(sql, args);
      if (!rows?.length) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, item: rows[0] });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al obtener usuario", detail: err?.message });
    }
  });

  // ───────────────── CREATE (WRITE) ─────────────────
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = CreateSchema.safeParse((req as any).body);
    if (!parsed.success) {
      const detail = parsed.error.issues.map((iss) => `${iss.path.join(".")}: ${iss.message}`).join("; ");
      return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
    }

    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;

    const data: any = normalizeForDB(pickAllowed(parsed.data));

    // regla: rol1 SIEMPRE fuerza su academia; rol3 debe indicar academia_id (o se lo pides en payload)
    if (academia_id) {
      data.academia_id = academia_id;
    } else {
      // superadmin
      if (!data.academia_id || !Number.isFinite(Number(data.academia_id)) || Number(data.academia_id) <= 0) {
        return reply.code(400).send({ ok: false, message: "academia_id es obligatorio para superadmin" });
      }
    }

    if (!data.nombre_usuario || !data.email || !data.password || !data.rut_usuario || !data.rol_id || !data.estado_id) {
      return reply.code(400).send({ ok: false, message: "Payload inválido (campos requeridos faltantes)" });
    }

    try {
      data.password = await argon2.hash(String(data.password));

      const [result]: any = await db.query(
        `INSERT INTO usuarios (academia_id, nombre_usuario, rut_usuario, email, password, rol_id, estado_id)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [data.academia_id, data.nombre_usuario, data.rut_usuario, data.email, data.password, data.rol_id, data.estado_id]
      );

      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        academia_id: data.academia_id,
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
          message: "Violación de clave foránea (academia_id, rol_id o estado_id inválido)",
          detail: err?.sqlMessage ?? err?.message,
        });
      }
      return reply.code(500).send({ ok: false, message: "Error al crear usuario", detail: err?.message });
    }
  });

  // ───────────────── UPDATE (WRITE) ─────────────────
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    noStore(reply);

    const pid = IdParam.safeParse((req as any).params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });
    const id = pid.data.id;

    const parsed = UpdateSchema.safeParse((req as any).body);
    if (!parsed.success) {
      const detail = parsed.error.issues.map((iss) => `${iss.path.join(".")}: ${iss.message}`).join("; ");
      return reply.code(400).send({ ok: false, message: "Payload inválido", detail });
    }

    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;

    // rol1: no puede editar usuarios de otra academia
    const okRow = await assertUserInAcademiaOr404(id, academia_id, reply);
    if (!okRow) return;

    const changes: any = normalizeForDB(pickAllowed(parsed.data));
    if (Object.keys(changes).length === 0) {
      return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
    }

    // rol1: PROHIBIDO mover academia_id
    if (academia_id && changes.academia_id !== undefined) {
      delete changes.academia_id;
    }

    try {
      if (typeof changes.password === "string") {
        changes.password = await argon2.hash(String(changes.password));
      }

      const setClauses: string[] = [];
      const values: any[] = [];

      if (changes.academia_id !== undefined) { setClauses.push("academia_id = ?"); values.push(changes.academia_id); }
      if (changes.nombre_usuario !== undefined) { setClauses.push("nombre_usuario = ?"); values.push(changes.nombre_usuario); }
      if (changes.rut_usuario !== undefined) { setClauses.push("rut_usuario = ?"); values.push(changes.rut_usuario); }
      if (changes.email !== undefined) { setClauses.push("email = ?"); values.push(changes.email); }
      if (changes.password !== undefined) { setClauses.push("password = ?"); values.push(changes.password); }
      if (changes.rol_id !== undefined) { setClauses.push("rol_id = ?"); values.push(changes.rol_id); }
      if (changes.estado_id !== undefined) { setClauses.push("estado_id = ?"); values.push(changes.estado_id); }

      if (setClauses.length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      values.push(id);

      // extra where para rol1 (bypass para rol3)
      let sql = `UPDATE usuarios SET ${setClauses.join(", ")} WHERE id = ?`;
      if (academia_id) {
        sql += ` AND academia_id = ?`;
        values.push(academia_id);
      }

      const [result]: any = await db.query(sql, values);

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrado" });
      }

      const { password, ...safe } = changes;
      return reply.send({ ok: true, updated: { id, ...safe } });
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
          message: "Violación de clave foránea (academia_id, rol_id o estado_id inválido)",
          detail: err?.sqlMessage ?? err?.message,
        });
      }
      return reply.code(500).send({ ok: false, message: "Error al actualizar usuario", detail: err?.message });
    }
  });

  // ───────────────── DELETE (WRITE) ─────────────────
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    noStore(reply);

    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;

    // rol1: no puede borrar fuera de su academia
    const okRow = await assertUserInAcademiaOr404(parsed.data.id, academia_id, reply);
    if (!okRow) return;

    try {
      const args: any[] = [parsed.data.id];
      let sql = "DELETE FROM usuarios WHERE id = ?";
      if (academia_id) {
        sql += " AND academia_id = ?";
        args.push(academia_id);
      }

      const [result]: any = await db.query(sql, args);

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrado" });
      }

      return reply.send({ ok: true, deleted: parsed.data.id });
    } catch (err: any) {
      if (err?.errno === 1451) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: hay registros vinculados a este usuario.",
          detail: err?.sqlMessage ?? err?.message,
        });
      }
      return reply.code(500).send({ ok: false, message: "Error al eliminar usuario", detail: err?.message });
    }
  });
}
