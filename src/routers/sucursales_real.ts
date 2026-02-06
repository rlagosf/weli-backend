// src/routers/sucursalesReal.ts
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: sucursales_real
 * Campos: id (PK), academia_id (FK), nombre (VARCHAR)
 * Recomendado: UNIQUE(academia_id, nombre)
 */

const IdParam = z.object({ id: z.coerce.number().int().positive() });

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres").max(100, "Máximo 100 caracteres"),
    // 👇 solo útil para superadmin (rol 3). Para rol 1 se fuerza desde token.
    academia_id: z.coerce.number().int().positive().optional(),
  })
  .strict();

const UpdateSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres").max(100, "Máximo 100 caracteres").optional(),
    // 👇 no permitimos mover sucursal de academia por API (evita cagazos)
    // academia_id: jamás por update
  })
  .strict();

const PageQuery = z.object({
  limit: z.coerce.number().int().positive().max(500).default(200),
  offset: z.coerce.number().int().nonnegative().default(0),
  q: z.string().trim().min(1).optional(),
});

function normalize(row: any) {
  return {
    id: Number(row.id),
    academia_id: Number(row.academia_id),
    nombre: String(row.nombre ?? ""),
  };
}

// ───────── auth helpers (academy scope) ─────────
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

/**
 * Retorna academia_id si aplica (rol 1/2), o null si es superadmin.
 * Si falta academia_id en rol 1/2 => 403.
 */
function getAcademiaIdOr403(req: any, reply: FastifyReply): number | null {
  const a = getAuth(req);
  if (!a || a.type !== "user") {
    reply.code(403).send({ ok: false, message: "FORBIDDEN" });
    return 0 as any;
  }

  if (Number(a.rol_id) === 3) return null; // superadmin: sin filtro

  const academia_id = Number(a.academia_id ?? 0);
  if (!Number.isFinite(academia_id) || academia_id <= 0) {
    reply.code(403).send({ ok: false, message: "ACADEMIA_REQUIRED" });
    return 0 as any;
  }
  return academia_id;
}

async function assertSucursalInAcademiaOr404(id: number, academia_id: number | null, reply: FastifyReply) {
  if (!academia_id) return true; // super bypass

  const [rows]: any = await db.query(
    "SELECT id FROM sucursales_real WHERE id = ? AND academia_id = ? LIMIT 1",
    [id, academia_id]
  );
  if (!rows?.length) {
    // multi-tenant: mejor 404 que 403 (no filtra existencia)
    reply.code(404).send({ ok: false, message: "Sucursal no encontrada" });
    return false;
  }
  return true;
}

// escape mínimo para LIKE
function escapeLike(s: string) {
  return s.replace(/[\\%_]/g, (m) => `\\${m}`);
}

export default async function sucursales_real(app: FastifyInstance) {
  // ✅ Permisos reales
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

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
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Query inválida", errors: parsed.error.flatten() });
    }

    const { limit, offset, q } = parsed.data;

    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;

    try {
      let sql = "SELECT id, academia_id, nombre FROM sucursales_real WHERE 1=1";
      const args: any[] = [];

      // filtro academia (rol 1/2)
      if (academia_id) {
        sql += " AND academia_id = ?";
        args.push(academia_id);
      }

      if (q) {
        sql += " AND nombre LIKE ? ESCAPE '\\\\'";
        args.push(`%${escapeLike(q)}%`);
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
      return reply.code(500).send({ ok: false, message: "Error al listar sucursales", detail: err?.message });
    }
  });

  // ─────────────────── OBTENER POR ID (READ) ───────────────────
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = parsed.data.id;

    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;

    const okOwn = await assertSucursalInAcademiaOr404(id, academia_id, reply);
    if (!okOwn) return;

    try {
      const whereAcademia = academia_id ? " AND academia_id = ?" : "";
      const params = academia_id ? [id, academia_id] : [id];

      const [rows]: any = await db.query(
        `SELECT id, academia_id, nombre
           FROM sucursales_real
          WHERE id = ?${whereAcademia}
          LIMIT 1`,
        params
      );

      reply.header("Cache-Control", "no-store");

      if (!rows?.length) return reply.code(404).send({ ok: false, message: "Sucursal no encontrada" });

      return reply.send({ ok: true, item: normalize(rows[0]) });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al obtener sucursal", detail: err?.message });
    }
  });

  // ─────────────────── CREAR (WRITE) ───────────────────
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const parsed = CreateSchema.parse((req as any).body);
      const nombre = parsed.nombre.trim();

      // academia_id:
      // - rol 1: SIEMPRE desde token
      // - rol 3: puede especificarla en body (si no, error)
      const auth = getAuth(req);
      const superAdmin = isSuper(req);

      let academia_id: number | null = null;

      if (!auth || auth.type !== "user") {
        return reply.code(403).send({ ok: false, message: "FORBIDDEN" });
      }

      if (superAdmin) {
        academia_id = parsed.academia_id ? Number(parsed.academia_id) : null;
        if (!academia_id) {
          return reply.code(400).send({ ok: false, message: "academia_id requerido para superadmin" });
        }
      } else {
        academia_id = Number(auth.academia_id ?? 0);
        if (!academia_id) return reply.code(403).send({ ok: false, message: "ACADEMIA_REQUIRED" });
      }

      const [result]: any = await db.query(
        "INSERT INTO sucursales_real (academia_id, nombre) VALUES (?, ?)",
        [academia_id, nombre]
      );

      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        academia_id,
        nombre,
      });
    } catch (err: any) {
      if (err instanceof ZodError) {
        const detail = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        return reply.code(400).send({ ok: false, message: "Datos inválidos", detail });
      }

      if (err?.errno === 1062) {
        // Idealmente UNIQUE(academia_id, nombre)
        return reply.code(409).send({ ok: false, message: "Ya existe una sucursal con ese nombre" });
      }

      return reply.code(500).send({ ok: false, message: "Error al crear sucursal", detail: err?.message });
    }
  });

  // ─────────────────── ACTUALIZAR (WRITE) ───────────────────
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pid = IdParam.safeParse((req as any).params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = pid.data.id;

    try {
      const body = UpdateSchema.parse((req as any).body);
      const changes: any = {};
      if (body.nombre !== undefined) changes.nombre = body.nombre.trim();

      if (Object.keys(changes).length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const academia_id = getAcademiaIdOr403(req, reply);
      if ((reply as any).sent) return;

      const okOwn = await assertSucursalInAcademiaOr404(id, academia_id, reply);
      if (!okOwn) return;

      const whereAcademia = academia_id ? " AND academia_id = ?" : "";
      const params: any[] = [];
      const setClauses: string[] = [];
      if (changes.nombre !== undefined) {
        setClauses.push("nombre = ?");
        params.push(changes.nombre);
      }

      params.push(id);
      if (academia_id) params.push(academia_id);

      const [result]: any = await db.query(
        `UPDATE sucursales_real
            SET ${setClauses.join(", ")}
          WHERE id = ?${whereAcademia}`,
        params
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

    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;

    const okOwn = await assertSucursalInAcademiaOr404(id, academia_id, reply);
    if (!okOwn) return;

    try {
      const whereAcademia = academia_id ? " AND academia_id = ?" : "";
      const params = academia_id ? [id, academia_id] : [id];

      const [result]: any = await db.query(
        `DELETE FROM sucursales_real WHERE id = ?${whereAcademia}`,
        params
      );

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "Sucursal no encontrada" });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: hay jugadores vinculados a esta sucursal",
          detail: err?.sqlMessage ?? err?.message,
        });
      }

      return reply.code(500).send({ ok: false, message: "Error al eliminar sucursal", detail: err?.message });
    }
  });
}
