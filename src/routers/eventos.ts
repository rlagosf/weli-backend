// src/routers/eventos.ts
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

const ACADEMIA_HEADER = "x-academia-id";

/**
 * Tabla: eventos
 *  id, academia_id, titulo, descripcion, fecha_inicio, fecha_fin, creado_en, actualizado_en
 */

type ReqUser = {
  id?: number;
  rol_id?: number;
  academia_id?: number | null;
};

const IdParam = z.object({
  id: z.string().regex(/^\d+$/),
});

const CreateSchema = z.object({
  titulo: z.string().min(1).max(200),
  descripcion: z.string().max(2000).optional().nullable(),
  fecha_inicio: z.string().min(10),
  fecha_fin: z.string().min(10),
});

const UpdateSchema = z.object({
  titulo: z.string().min(1).max(200).optional(),
  descripcion: z.string().max(2000).optional().nullable(),
  fecha_inicio: z.string().min(10).optional(),
  fecha_fin: z.string().min(10).optional(),
});

const PageQuery = z.object({
  limit: z.coerce.number().int().positive().max(200).optional().default(50),
  offset: z.coerce.number().int().nonnegative().optional().default(0),
});

// Normaliza fecha de ISO o 'YYYY-MM-DD HH:MM:SS' a 'YYYY-MM-DD HH:MM:SS'
function toSQLDateTime(input: string): string | null {
  if (!input) return null;
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(input)) return input;

  const d = new Date(input);
  if (Number.isNaN(d.valueOf())) return null;

  const pad = (n: number) => String(n).padStart(2, "0");
  const yyyy = d.getFullYear();
  const mm = pad(d.getMonth() + 1);
  const dd = pad(d.getDate());
  const HH = pad(d.getHours());
  const MM = pad(d.getMinutes());
  const SS = pad(d.getSeconds());
  return `${yyyy}-${mm}-${dd} ${HH}:${MM}:${SS}`;
}

function sendDbError(reply: FastifyReply, message: string, err: any) {
  return reply.code(500).send({
    ok: false,
    message,
    error: err?.sqlMessage || err?.message || String(err),
    errno: err?.errno,
    code: err?.code,
  });
}

/**
 * ✅ Scope multi-academia:
 * - rol 1/2: usa req.user.academia_id
 * - rol 3: usa header x-academia-id
 */
function getAcademiaScope(req: FastifyRequest, reply: FastifyReply): number | null {
  const user = (req as any).user as ReqUser | undefined;
  const rol = Number(user?.rol_id ?? 0);

  // Admin/Staff: academia amarrada al usuario
  if (rol === 1 || rol === 2) {
    const a = Number(user?.academia_id ?? 0);
    if (!Number.isFinite(a) || a <= 0) {
      reply.code(403).send({ ok: false, message: "Academia no asignada al usuario." });
      return null;
    }
    return a;
  }

  // Superadmin: academia por header
  if (rol === 3) {
    const raw = (req.headers as any)?.[ACADEMIA_HEADER];
    const v = Array.isArray(raw) ? raw[0] : raw;
    const a = Number(v);
    if (!Number.isFinite(a) || a <= 0) {
      reply.code(403).send({ ok: false, message: "Debes seleccionar una academia." });
      return null;
    }
    return a;
  }

  reply.code(403).send({ ok: false, message: "No autorizado." });
  return null;
}

export default async function eventos(app: FastifyInstance) {
  // 🔐 Roles permitidos: 1, 2, 3
  const onlyRoles123 = [requireAuth, requireRoles([1, 2, 3])];

  app.get("/health", async () => ({
    module: "eventos",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // ✅ Público (solo lectura): próximos eventos (GLOBAL)
  // Si luego quieres: hacerlo filtrable por academia con query param.
  app.get("/public", async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = PageQuery.safeParse(req.query);
    const { limit, offset } = parsed.success ? parsed.data : { limit: 50, offset: 0 };

    try {
      const [rows]: any = await db.query(
        `SELECT id, titulo, descripcion, fecha_inicio, fecha_fin, creado_en, actualizado_en
           FROM eventos
          WHERE fecha_fin >= NOW()
          ORDER BY fecha_inicio ASC, id ASC
          LIMIT ? OFFSET ?`,
        [Number(limit), Number(offset)]
      );
      return reply.send({ ok: true, items: rows, limit, offset });
    } catch (err: any) {
      req.log.error({ err }, "GET /eventos/public failed");
      return sendDbError(reply, "Error al listar eventos públicos", err);
    }
  });

  // GET /eventos (rol 1/2/3, filtrado por academia)
  app.get("/", { preHandler: onlyRoles123 }, async (req, reply) => {
    const academiaId = getAcademiaScope(req, reply);
    if (!academiaId) return;

    const parsed = PageQuery.safeParse(req.query);
    const { limit, offset } = parsed.success ? parsed.data : { limit: 50, offset: 0 };

    try {
      const [rows]: any = await db.query(
        `SELECT id, academia_id, titulo, descripcion, fecha_inicio, fecha_fin, creado_en, actualizado_en
           FROM eventos
          WHERE academia_id = ?
          ORDER BY fecha_inicio DESC, id DESC
          LIMIT ? OFFSET ?`,
        [academiaId, Number(limit), Number(offset)]
      );

      return reply.send({ ok: true, items: rows, limit, offset });
    } catch (err: any) {
      req.log.error({ err }, "GET /eventos failed");
      return sendDbError(reply, "Error al listar eventos", err);
    }
  });

  // GET /eventos/:id (rol 1/2/3, filtrado por academia)
  app.get("/:id", { preHandler: onlyRoles123 }, async (req, reply) => {
    const academiaId = getAcademiaScope(req, reply);
    if (!academiaId) return;

    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = Number(parsed.data.id);

    try {
      const [rows]: any = await db.query(
        `SELECT id, academia_id, titulo, descripcion, fecha_inicio, fecha_fin, creado_en, actualizado_en
           FROM eventos
          WHERE id = ? AND academia_id = ?
          LIMIT 1`,
        [id, academiaId]
      );

      if (!rows.length) return reply.code(404).send({ ok: false, message: "No encontrado" });
      return reply.send({ ok: true, item: rows[0] });
    } catch (err: any) {
      req.log.error({ err, id }, "GET /eventos/:id failed");
      return sendDbError(reply, "Error al obtener evento", err);
    }
  });

  // POST /eventos (rol 1/2/3, inserta academia_id)
  app.post("/", { preHandler: onlyRoles123 }, async (req, reply) => {
    const academiaId = getAcademiaScope(req, reply);
    if (!academiaId) return;

    const parsed = CreateSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Payload inválido", errors: parsed.error.flatten() });
    }

    const { titulo, descripcion, fecha_inicio, fecha_fin } = parsed.data;
    const ini = toSQLDateTime(fecha_inicio);
    const fin = toSQLDateTime(fecha_fin);

    if (!ini || !fin) return reply.code(400).send({ ok: false, message: "Formato de fecha inválido" });
    if (new Date(ini) >= new Date(fin)) {
      return reply.code(400).send({ ok: false, message: "fecha_fin debe ser mayor que fecha_inicio" });
    }

    try {
      const [result]: any = await db.query(
        `INSERT INTO eventos (academia_id, titulo, descripcion, fecha_inicio, fecha_fin, creado_en, actualizado_en)
         VALUES (?, ?, ?, ?, ?, NOW(), NOW())`,
        [academiaId, titulo, descripcion ?? null, ini, fin]
      );

      const id = result.insertId;

      const [rows]: any = await db.query(
        `SELECT id, academia_id, titulo, descripcion, fecha_inicio, fecha_fin, creado_en, actualizado_en
           FROM eventos
          WHERE id = ? AND academia_id = ?
          LIMIT 1`,
        [id, academiaId]
      );

      return reply.code(201).send({ ok: true, item: rows[0] });
    } catch (err: any) {
      req.log.error({ err }, "POST /eventos failed");
      return sendDbError(reply, "Error al crear evento", err);
    }
  });

  // PUT /eventos/:id (rol 1/2/3, update por academia)
  app.put("/:id", { preHandler: onlyRoles123 }, async (req, reply) => {
    const academiaId = getAcademiaScope(req, reply);
    if (!academiaId) return;

    const pid = IdParam.safeParse(req.params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });
    const id = Number(pid.data.id);

    const parsed = UpdateSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Payload inválido", errors: parsed.error.flatten() });
    }

    const fields: string[] = [];
    const values: any[] = [];

    if (parsed.data.titulo !== undefined) {
      fields.push("titulo = ?");
      values.push(parsed.data.titulo);
    }
    if (parsed.data.descripcion !== undefined) {
      fields.push("descripcion = ?");
      values.push(parsed.data.descripcion ?? null);
    }

    let iniTmp: string | null = null;
    let finTmp: string | null = null;

    if (parsed.data.fecha_inicio !== undefined) {
      const ini = toSQLDateTime(parsed.data.fecha_inicio);
      if (!ini) return reply.code(400).send({ ok: false, message: "fecha_inicio inválida" });
      iniTmp = ini;
      fields.push("fecha_inicio = ?");
      values.push(ini);
    }

    if (parsed.data.fecha_fin !== undefined) {
      const fin = toSQLDateTime(parsed.data.fecha_fin);
      if (!fin) return reply.code(400).send({ ok: false, message: "fecha_fin inválida" });
      finTmp = fin;
      fields.push("fecha_fin = ?");
      values.push(fin);
    }

    if (iniTmp && finTmp && new Date(iniTmp) >= new Date(finTmp)) {
      return reply.code(400).send({ ok: false, message: "fecha_fin debe ser mayor que fecha_inicio" });
    }

    if (fields.length === 0) return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });

    try {
      const sql = `UPDATE eventos
                     SET ${fields.join(", ")}, actualizado_en = NOW()
                   WHERE id = ? AND academia_id = ?`;
      values.push(id, academiaId);

      const [result]: any = await db.query(sql, values);
      if (!result?.affectedRows) return reply.code(404).send({ ok: false, message: "No encontrado" });

      const [rows]: any = await db.query(
        `SELECT id, academia_id, titulo, descripcion, fecha_inicio, fecha_fin, creado_en, actualizado_en
           FROM eventos
          WHERE id = ? AND academia_id = ?
          LIMIT 1`,
        [id, academiaId]
      );

      return reply.send({ ok: true, item: rows[0] });
    } catch (err: any) {
      req.log.error({ err, id }, "PUT /eventos/:id failed");
      return sendDbError(reply, "Error al actualizar evento", err);
    }
  });

  // DELETE /eventos/:id (rol 1/2/3, delete por academia)
  app.delete("/:id", { preHandler: onlyRoles123 }, async (req, reply) => {
    const academiaId = getAcademiaScope(req, reply);
    if (!academiaId) return;

    const parsed = IdParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });
    const id = Number(parsed.data.id);

    try {
      const [result]: any = await db.query(
        "DELETE FROM eventos WHERE id = ? AND academia_id = ?",
        [id, academiaId]
      );

      if (!result?.affectedRows) return reply.code(404).send({ ok: false, message: "No encontrado" });
      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      req.log.error({ err, id }, "DELETE /eventos/:id failed");

      if (err?.errno === 1451 || String(err?.code || "").includes("ER_ROW_IS_REFERENCED")) {
        return reply.code(409).send({
          ok: false,
          message: "No se puede eliminar: el evento está asociado a otros registros",
          error: err?.sqlMessage || err?.message,
        });
      }

      return sendDbError(reply, "Error al eliminar evento", err);
    }
  });
}
