// src/routers/convocatorias_historico.ts
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db";
import {
  requireAuth,
  requireRoles,
  getEffectiveAcademiaId, // ✅ estándar único
} from "../middlewares/authz";

/* ───────────────────────────────
   ZOD SCHEMAS
─────────────────────────────── */
const CreateSchema = z.object({
  evento_id: z.coerce.number().int().positive(),
  convocatoria_id: z.coerce.number().int().positive(),
  fecha_generacion: z.string().optional(),
  listado_base64: z.string().min(10),
});

const IdParam = z.object({ id: z.coerce.number().int().positive() });

const EventoConvParam = z.object({
  evento_id: z.coerce.number().int().positive(),
  convocatoria_id: z.coerce.number().int().positive(),
});

const PaginationQuery = z.object({
  page: z.coerce.number().int().positive().optional(),
  pageSize: z.coerce.number().int().positive().optional(),
});

/* ───────────────────────────────
   UTILS
─────────────────────────────── */
const stripDataUrlPrefix = (s: string) => {
  const idx = s.indexOf(",");
  return s.startsWith("data:") && idx > -1 ? s.slice(idx + 1) : s;
};

const approxBytes = (b64: string) => Math.floor((b64.length * 3) / 4);
const MAX_BYTES = Number(process.env.CONVOC_HIST_MAX_BYTES || 12 * 1024 * 1024);

function getUserIdOrNull(req: any): number | null {
  const a = (req as any).auth;
  if (!a || typeof a !== "object") return null;
  if (a.type !== "user") return null;
  const n = Number(a.user_id ?? 0);
  return Number.isFinite(n) && n > 0 ? n : null;
}

/* ───────────────────────────────
   ROUTER
─────────────────────────────── */
export default async function convocatorias_historico(app: FastifyInstance) {
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  app.get("/health", { preHandler: canRead }, async () => ({
    module: "convocatorias_historico",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // LISTAR (SIEMPRE scoping por academia efectiva)
  app.get("/", { preHandler: canRead }, async (req, reply) => {
    try {
      const parsed = PaginationQuery.safeParse((req as any).query);
      const page = parsed.success && parsed.data.page ? Number(parsed.data.page) : 1;
      const size = parsed.success && parsed.data.pageSize ? Number(parsed.data.pageSize) : 50;

      const limit = Math.min(Math.max(size, 1), 200);
      const offset = (Math.max(page, 1) - 1) * limit;

      const academia_id = getEffectiveAcademiaId(req);

      const [rows]: any = await db.query(
        `
        SELECT h.id, h.evento_id, h.convocatoria_id, h.fecha_generacion, h.generado_por
          FROM convocatorias_historico h
          JOIN eventos e ON e.id = h.evento_id
         WHERE e.academia_id = ?
         ORDER BY h.fecha_generacion DESC, h.id DESC
         LIMIT ? OFFSET ?
        `,
        [academia_id, limit, offset]
      );

      return reply.send({ ok: true, items: rows, page, pageSize: limit, academia_id });
    } catch (e: any) {
      const code =
        e?.statusCode && Number.isFinite(e.statusCode) ? Number(e.statusCode) : 500;
      return reply.code(code).send({ ok: false, message: "Error al listar", error: e?.message });
    }
  });

  // Obtener por evento + convocatoria (SIEMPRE scoping)
  app.get(
    "/evento/:evento_id/convocatoria/:convocatoria_id",
    { preHandler: canRead },
    async (req, reply) => {
      const p = EventoConvParam.safeParse((req as any).params);
      if (!p.success) return reply.code(400).send({ ok: false, message: "Parámetros inválidos" });

      const { evento_id, convocatoria_id } = p.data;

      try {
        const academia_id = getEffectiveAcademiaId(req);

        const [rows]: any = await db.query(
          `
          SELECT h.id, h.evento_id, h.convocatoria_id, h.fecha_generacion, h.generado_por
            FROM convocatorias_historico h
            JOIN eventos e ON e.id = h.evento_id
           WHERE h.evento_id = ?
             AND h.convocatoria_id = ?
             AND e.academia_id = ?
           ORDER BY h.fecha_generacion DESC, h.id DESC
          `,
          [evento_id, convocatoria_id, academia_id]
        );

        return reply.send({ ok: true, items: rows, academia_id });
      } catch (e: any) {
        const code =
          e?.statusCode && Number.isFinite(e.statusCode) ? Number(e.statusCode) : 500;
        return reply.code(code).send({
          ok: false,
          message: "Error al obtener registros del evento",
          error: e?.message,
        });
      }
    }
  );

  // Ver PDF (SIEMPRE scoping)
  app.get("/ver/:id", { preHandler: canRead }, async (req, reply) => {
    const p = IdParam.safeParse((req as any).params);
    if (!p.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const { id } = p.data;

    try {
      const academia_id = getEffectiveAcademiaId(req);

      const [rows]: any = await db.query(
        `
        SELECT h.listado_base64
          FROM convocatorias_historico h
          JOIN eventos e ON e.id = h.evento_id
         WHERE h.id = ?
           AND e.academia_id = ?
         LIMIT 1
        `,
        [id, academia_id]
      );

      if (!rows?.length) return reply.code(404).send({ ok: false, message: "No encontrado" });

      const pure = stripDataUrlPrefix(String(rows[0].listado_base64 || ""));
      const buf = Buffer.from(pure, "base64");

      reply.header("Content-Type", "application/pdf");
      reply.header("Content-Disposition", `inline; filename="convocatoria_${id}.pdf"`);
      return reply.send(buf);
    } catch (e: any) {
      const code =
        e?.statusCode && Number.isFinite(e.statusCode) ? Number(e.statusCode) : 500;
      return reply.code(code).send({ ok: false, message: "Error al generar PDF", error: e?.message });
    }
  });

  // OBTENER POR ID (SIEMPRE scoping)
  app.get("/:id", { preHandler: canRead }, async (req, reply) => {
    const p = IdParam.safeParse((req as any).params);
    if (!p.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const { id } = p.data;

    try {
      const academia_id = getEffectiveAcademiaId(req);

      const [rows]: any = await db.query(
        `
        SELECT h.*
          FROM convocatorias_historico h
          JOIN eventos e ON e.id = h.evento_id
         WHERE h.id = ?
           AND e.academia_id = ?
         LIMIT 1
        `,
        [id, academia_id]
      );

      if (!rows?.length) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, item: rows[0], academia_id });
    } catch (e: any) {
      const code =
        e?.statusCode && Number.isFinite(e.statusCode) ? Number(e.statusCode) : 500;
      return reply.code(code).send({ ok: false, message: "Error al obtener registro", error: e?.message });
    }
  });

  // Crear registro (VALIDA evento dentro de academia efectiva)
  app.post("/", { preHandler: canWrite }, async (req, reply) => {
    const parsed = CreateSchema.safeParse((req as any).body);
    if (!parsed.success) {
      return reply.code(400).send({
        ok: false,
        message: "Payload inválido",
        errors: parsed.error.flatten(),
      });
    }

    const { evento_id, convocatoria_id, listado_base64 } = parsed.data;
    let { fecha_generacion } = parsed.data;

    try {
      const academia_id = getEffectiveAcademiaId(req);

      // ✅ Validar evento pertenece a academia efectiva
      const [chk]: any = await db.query(
        `SELECT id FROM eventos WHERE id = ? AND academia_id = ? LIMIT 1`,
        [evento_id, academia_id]
      );
      if (!chk?.length) return reply.code(403).send({ ok: false, message: "FORBIDDEN_EVENTO" });

      const pure = stripDataUrlPrefix(listado_base64);
      const bytes = approxBytes(pure);
      if (bytes > MAX_BYTES) {
        return reply.code(413).send({
          ok: false,
          message: `El PDF excede el límite permitido (${Math.floor(MAX_BYTES / (1024 * 1024))} MB).`,
        });
      }

      let fechaMySQL: string | null = null;
      if (fecha_generacion) {
        const d = new Date(fecha_generacion);
        if (!isNaN(d.getTime())) fechaMySQL = d.toISOString().slice(0, 19).replace("T", " ");
      }

      const generado_por = getUserIdOrNull(req); // ✅ auditable (admin/super/s)

      const sql = `
        INSERT INTO convocatorias_historico
          (evento_id, convocatoria_id, fecha_generacion, listado_base64, generado_por)
        VALUES (?, ?, ${fechaMySQL ? "?" : "NOW()"}, ?, ?)
      `;

      const params = fechaMySQL
        ? [evento_id, convocatoria_id, fechaMySQL, pure, generado_por]
        : [evento_id, convocatoria_id, pure, generado_por];

      const [result]: any = await db.query(sql, params);

      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        evento_id,
        convocatoria_id,
        academia_id,
        fecha_generacion: fechaMySQL ?? new Date().toISOString(),
      });
    } catch (e: any) {
      const code =
        e?.statusCode && Number.isFinite(e.statusCode) ? Number(e.statusCode) : 500;
      return reply.code(code).send({ ok: false, message: "Error al crear registro", error: e?.message });
    }
  });
}
