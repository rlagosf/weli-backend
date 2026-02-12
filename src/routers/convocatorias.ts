// src/routers/convocatorias.ts
import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { z } from "zod";
import { db } from "../db";
import {
  requireAuth,
  requireRoles,
  getEffectiveAcademiaId, // ✅ estándar único
} from "../middlewares/authz";

// Helpers
const b2i = (v: boolean | number | undefined | null) => (v ? 1 : 0);
const i2b = (v: any) => (Number(v) ? true : false);

// Validadores
const ConvocatoriaSchema = z.object({
  jugador_rut: z.number().int().positive(),
  fecha_partido: z.string().refine((x) => !Number.isNaN(Date.parse(x)), "fecha_partido inválida"),
  evento_id: z.number().int().positive(),
  asistio: z.boolean().optional().default(false),
  titular: z.boolean().optional().default(false),
  observaciones: z.string().nullable().optional(),
});

const OneOrManySchema = z.union([ConvocatoriaSchema, z.array(ConvocatoriaSchema).min(1)]);

const IdParam = z.object({ id: z.coerce.number().int().positive() });
const EventoParam = z.object({ evento_id: z.coerce.number().int().positive() });

const ConvocatoriaParam = z.object({
  evento_id: z.coerce.number().int().positive(),
  convocatoria_id: z.coerce.number().int().positive(),
});

const PaginationQuery = z.object({
  page: z.coerce.number().int().positive().optional(),
  pageSize: z.coerce.number().int().positive().optional(),
});

async function assertEventoInAcademiaOrReply(
  evento_id: number,
  academia_id: number,
  reply: FastifyReply
): Promise<boolean> {
  const [rows]: any = await db.query(
    "SELECT id FROM eventos WHERE id = ? AND academia_id = ? LIMIT 1",
    [evento_id, academia_id]
  );
  if (!rows?.length) {
    reply.code(403).send({ ok: false, message: "FORBIDDEN_EVENTO" });
    return false;
  }
  return true;
}

async function assertConvocatoriaIdInAcademiaOrReply(
  id: number,
  academia_id: number,
  reply: FastifyReply
): Promise<boolean> {
  const [rows]: any = await db.query(
    `
    SELECT c.id
      FROM convocatorias c
      JOIN eventos e ON e.id = c.evento_id
     WHERE c.id = ?
       AND e.academia_id = ?
     LIMIT 1
    `,
    [id, academia_id]
  );

  if (!rows?.length) {
    // 404 para no filtrar info cross-tenant
    reply.code(404).send({ ok: false, message: "No encontrado" });
    return false;
  }
  return true;
}

/* ───────── Router ───────── */

export default async function convocatorias(app: FastifyInstance) {
  // ✅ Read: rol 1 y 3
  const canRead = [requireAuth, requireRoles([1, 3])];
  // ✅ Write: rol 1 y 3 (regla platino: superadmin también crea/edita/borrar dentro de academia objetivo)
  const canWrite = [requireAuth, requireRoles([1, 3])];

  // ================= HEALTH =================
  app.get("/health", { preHandler: canRead }, async () => ({
    module: "convocatorias",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // ================= GET TODOS =================
  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const q = PaginationQuery.safeParse(req.query);
      const page = q.success && q.data.page ? Number(q.data.page) : 1;
      const pageSize = q.success && q.data.pageSize ? Math.min(Number(q.data.pageSize), 200) : 50;

      const safePage = Math.max(page, 1);
      const limit = Math.min(Math.max(pageSize, 1), 200);
      const offset = (safePage - 1) * limit;

      const academia_id = getEffectiveAcademiaId(req);

      const [rows] = await db.query(
        `
        SELECT c.id, c.jugador_rut, c.fecha_partido, c.evento_id, c.convocatoria_id,
               c.asistio, c.titular, c.observaciones
          FROM convocatorias c
          JOIN eventos e ON e.id = c.evento_id
         WHERE e.academia_id = ?
         ORDER BY c.fecha_partido DESC, c.id DESC
         LIMIT ? OFFSET ?
        `,
        [academia_id, limit, offset]
      );

      const items = (rows as any[]).map((r) => ({
        ...r,
        asistio: i2b(r.asistio),
        titular: i2b(r.titular),
      }));

      return reply.send({ ok: true, items, page: safePage, pageSize: limit, academia_id });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? Number(err.statusCode) : 500;
      return reply.code(code).send({ ok: false, message: "Error al listar convocatorias", error: err?.message });
    }
  });

  // ================= GET POR EVENTO =================
  app.get("/evento/:evento_id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const p = EventoParam.safeParse(req.params);
    if (!p.success) return reply.code(400).send({ ok: false, message: "evento_id inválido" });

    const q = PaginationQuery.safeParse(req.query);
    const page = q.success && q.data.page ? Number(q.data.page) : 1;
    const pageSize = q.success && q.data.pageSize ? Math.min(Number(q.data.pageSize), 200) : 50;

    const safePage = Math.max(page, 1);
    const limit = Math.min(Math.max(pageSize, 1), 200);
    const offset = (safePage - 1) * limit;

    const evento_id = p.data.evento_id;

    try {
      const academia_id = getEffectiveAcademiaId(req);

      const okEvento = await assertEventoInAcademiaOrReply(evento_id, academia_id, reply);
      if (!okEvento) return;

      const [rows] = await db.query(
        `
        SELECT c.id, c.jugador_rut, c.fecha_partido, c.evento_id, c.convocatoria_id,
               c.asistio, c.titular, c.observaciones
          FROM convocatorias c
          JOIN eventos e ON e.id = c.evento_id
         WHERE c.evento_id = ?
           AND e.academia_id = ?
         ORDER BY c.fecha_partido DESC, c.id DESC
         LIMIT ? OFFSET ?
        `,
        [evento_id, academia_id, limit, offset]
      );

      const items = (rows as any[]).map((r) => ({
        ...r,
        asistio: i2b(r.asistio),
        titular: i2b(r.titular),
      }));

      return reply.send({ ok: true, items, page: safePage, pageSize: limit, academia_id });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? Number(err.statusCode) : 500;
      return reply.code(code).send({ ok: false, message: "Error al listar por evento", error: err?.message });
    }
  });

  // ================= GET por evento + convocatoria_id =================
  app.get(
    "/evento/:evento_id/convocatoria/:convocatoria_id",
    { preHandler: canRead },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const p = ConvocatoriaParam.safeParse(req.params);
      if (!p.success) return reply.code(400).send({ ok: false, message: "Parámetros inválidos" });

      const { evento_id, convocatoria_id } = p.data;

      try {
        const academia_id = getEffectiveAcademiaId(req);

        const okEvento = await assertEventoInAcademiaOrReply(evento_id, academia_id, reply);
        if (!okEvento) return;

        const [rows]: any = await db.query(
          `
          SELECT c.id, c.jugador_rut, c.fecha_partido, c.evento_id, c.convocatoria_id,
                 c.asistio, c.titular, c.observaciones
            FROM convocatorias c
            JOIN eventos e ON e.id = c.evento_id
           WHERE c.evento_id = ?
             AND c.convocatoria_id = ?
             AND e.academia_id = ?
           ORDER BY c.jugador_rut ASC
          `,
          [evento_id, convocatoria_id, academia_id]
        );

        const items = (rows ?? []).map((r: any) => ({
          ...r,
          asistio: i2b(r.asistio),
          titular: i2b(r.titular),
        }));

        return reply.send({ ok: true, items, academia_id });
      } catch (err: any) {
        const code = err?.statusCode && Number.isFinite(err.statusCode) ? Number(err.statusCode) : 500;
        return reply.code(code).send({
          ok: false,
          message: "Error al obtener jugadores de la convocatoria",
          error: err?.message,
        });
      }
    }
  );

  // ================= GET por ID =================
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const p = IdParam.safeParse(req.params);
    if (!p.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = p.data.id;

    try {
      const academia_id = getEffectiveAcademiaId(req);

      const [rows]: any = await db.query(
        `
        SELECT c.id, c.jugador_rut, c.fecha_partido, c.evento_id, c.convocatoria_id,
               c.asistio, c.titular, c.observaciones
          FROM convocatorias c
          JOIN eventos e ON e.id = c.evento_id
         WHERE c.id = ?
           AND e.academia_id = ?
         LIMIT 1
        `,
        [id, academia_id]
      );

      if (!rows?.length) return reply.code(404).send({ ok: false, message: "No encontrado" });

      const r = rows[0];
      return reply.send({
        ok: true,
        item: { ...r, asistio: i2b(r.asistio), titular: i2b(r.titular) },
        academia_id,
      });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? Number(err.statusCode) : 500;
      return reply.code(code).send({ ok: false, message: "Error al obtener convocatoria", error: err?.message });
    }
  });

  // ================= POST (WRITE) =================
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    // Validar tamaño (1 MB)
    const sizeBytes = Buffer.byteLength(JSON.stringify(req.body ?? {}));
    if (sizeBytes > 1024 * 1024) {
      return reply.code(413).send({ ok: false, message: "Payload demasiado grande (máx 1 MB)" });
    }

    const parsed = OneOrManySchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Payload inválido", errors: parsed.error.flatten() });
    }

    const data = Array.isArray(parsed.data) ? parsed.data : [parsed.data];
    if (data.length > 100) {
      return reply.code(413).send({ ok: false, message: `Listado demasiado grande (${data.length}). Máximo = 100.` });
    }

    const eventoIds = Array.from(new Set(data.map((d) => d.evento_id)));
    if (eventoIds.length !== 1) {
      return reply.code(400).send({ ok: false, message: "Todos los registros deben tener el mismo evento_id" });
    }

    const evento_id = eventoIds[0];

    try {
      const academia_id = getEffectiveAcademiaId(req);

      const okEvento = await assertEventoInAcademiaOrReply(evento_id, academia_id, reply);
      if (!okEvento) return;

      const [rowsMax]: any = await db.query(
        `
        SELECT COALESCE(MAX(c.convocatoria_id), 0) AS maxConv
          FROM convocatorias c
          JOIN eventos e ON e.id = c.evento_id
         WHERE c.evento_id = ?
           AND e.academia_id = ?
        `,
        [evento_id, academia_id]
      );

      const nextConvId = (rowsMax?.[0]?.maxConv || 0) + 1;

      const values = data.map((d) => [
        d.jugador_rut,
        d.fecha_partido,
        d.evento_id,
        nextConvId,
        b2i(d.asistio),
        b2i(d.titular),
        d.observaciones ?? null,
      ]);

      await db.query(
        `
        INSERT INTO convocatorias
          (jugador_rut, fecha_partido, evento_id, convocatoria_id, asistio, titular, observaciones)
        VALUES ?
        `,
        [values]
      );

      return reply.code(201).send({
        ok: true,
        evento_id,
        convocatoria_id: nextConvId,
        inserted: values.length,
        academia_id,
      });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? Number(err.statusCode) : 500;
      return reply.code(code).send({ ok: false, message: "Error al crear convocatoria(s)", error: err?.message });
    }
  });

  // ================= PUT (WRITE) =================
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const idParsed = IdParam.safeParse(req.params);
    if (!idParsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const bodyParsed = ConvocatoriaSchema.partial().safeParse(req.body);
    if (!bodyParsed.success) {
      return reply.code(400).send({ ok: false, message: "Payload inválido", errors: bodyParsed.error.flatten() });
    }

    const id = idParsed.data.id;
    const data = bodyParsed.data;

    try {
      const academia_id = getEffectiveAcademiaId(req);

      const okRow = await assertConvocatoriaIdInAcademiaOrReply(id, academia_id, reply);
      if (!okRow) return;

      if (data.evento_id !== undefined) {
        const okEvento = await assertEventoInAcademiaOrReply(Number(data.evento_id), academia_id, reply);
        if (!okEvento) return;
      }

      const fields: string[] = [];
      const values: any[] = [];

      if (data.jugador_rut !== undefined) { fields.push("jugador_rut = ?"); values.push(data.jugador_rut); }
      if (data.fecha_partido !== undefined) { fields.push("fecha_partido = ?"); values.push(data.fecha_partido); }
      if (data.evento_id !== undefined) { fields.push("evento_id = ?"); values.push(data.evento_id); }
      if (data.asistio !== undefined) { fields.push("asistio = ?"); values.push(b2i(data.asistio)); }
      if (data.titular !== undefined) { fields.push("titular = ?"); values.push(b2i(data.titular)); }
      if (data.observaciones !== undefined) { fields.push("observaciones = ?"); values.push(data.observaciones ?? null); }

      if (fields.length === 0) return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });

      const [result]: any = await db.query(
        `UPDATE convocatorias SET ${fields.join(", ")} WHERE id = ?`,
        [...values, id]
      );

      if (Number(result?.affectedRows ?? 0) === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrado" });
      }

      return reply.send({ ok: true, updated: { id, ...data }, academia_id });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? Number(err.statusCode) : 500;
      return reply.code(code).send({ ok: false, message: "Error al actualizar", error: err?.message });
    }
  });

  // ================= DELETE (WRITE) =================
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const p = IdParam.safeParse(req.params);
    if (!p.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = p.data.id;

    try {
      const academia_id = getEffectiveAcademiaId(req);

      const okRow = await assertConvocatoriaIdInAcademiaOrReply(id, academia_id, reply);
      if (!okRow) return;

      const [result]: any = await db.query("DELETE FROM convocatorias WHERE id = ?", [id]);
      if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, deleted: id, academia_id });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? Number(err.statusCode) : 500;
      return reply.code(code).send({ ok: false, message: "Error al eliminar", error: err?.message });
    }
  });
}
