// src/routers/convocatorias_historico.ts
import { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/* ───────────────────────────────
   ZOD SCHEMAS
─────────────────────────────── */
const CreateSchema = z.object({
  evento_id: z.coerce.number().int().positive(),
  convocatoria_id: z.coerce.number().int().positive(),
  fecha_generacion: z.string().optional(),
  listado_base64: z.string().min(10),
});

const IdParam = z.object({
  id: z.string().regex(/^\d+$/, "ID inválido"),
});

const EventoConvParam = z.object({
  evento_id: z.string().regex(/^\d+$/, "evento_id inválido"),
  convocatoria_id: z.string().regex(/^\d+$/, "convocatoria_id inválido"),
});

const PaginationQuery = z.object({
  page: z.string().regex(/^\d+$/).optional(),
  pageSize: z.string().regex(/^\d+$/).optional(),
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

/* ───────────────────────────────
   ROUTER
─────────────────────────────── */
export default async function convocatorias_historico(app: FastifyInstance) {
  // ✅ Ambos roles pueden ver y (según tu requerimiento) generar historial
  const canRead = [requireAuth, requireRoles([1, 2])];
  const canWrite = [requireAuth, requireRoles([1, 2])]; // si algún día decides “solo admin crea”, cambias a [1]

  // Health (roles 1/2)
  app.get("/health", { preHandler: canRead }, async () => ({
    module: "convocatorias_historico",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // LISTAR (rol 1 y 2)
  app.get("/", { preHandler: canRead }, async (req, reply) => {
    try {
      const parsed = PaginationQuery.safeParse((req as any).query);
      const page = parsed.success && parsed.data.page ? Number(parsed.data.page) : 1;
      const size = parsed.success && parsed.data.pageSize ? Number(parsed.data.pageSize) : 50;

      const limit = Math.min(Math.max(size, 1), 200);
      const offset = (Math.max(page, 1) - 1) * limit;

      const [rows]: any = await db.query(
        `SELECT id, evento_id, convocatoria_id, fecha_generacion, generado_por
           FROM convocatorias_historico
          ORDER BY fecha_generacion DESC, id DESC
          LIMIT ? OFFSET ?`,
        [limit, offset]
      );

      return reply.send({ ok: true, items: rows, page, pageSize: limit });
    } catch (e: any) {
      return reply.code(500).send({ ok: false, message: "Error al listar", error: e?.message });
    }
  });

  // Obtener por evento + convocatoria (rol 1 y 2)
  app.get(
    "/evento/:evento_id/convocatoria/:convocatoria_id",
    { preHandler: canRead },
    async (req, reply) => {
      const p = EventoConvParam.safeParse((req as any).params);
      if (!p.success) return reply.code(400).send({ ok: false, message: "Parámetros inválidos" });

      const evento_id = Number(p.data.evento_id);
      const convocatoria_id = Number(p.data.convocatoria_id);

      try {
        const [rows]: any = await db.query(
          `SELECT id, evento_id, convocatoria_id, fecha_generacion, generado_por
             FROM convocatorias_historico
            WHERE evento_id = ? AND convocatoria_id = ?
            ORDER BY fecha_generacion DESC, id DESC`,
          [evento_id, convocatoria_id]
        );

        return reply.send({ ok: true, items: rows });
      } catch (e: any) {
        return reply.code(500).send({
          ok: false,
          message: "Error al obtener registros del evento",
          error: e?.message,
        });
      }
    }
  );

  // Ver PDF (rol 1 y 2) ✅ (IMPORTANTE: antes que "/:id")
  app.get("/ver/:id", { preHandler: canRead }, async (req, reply) => {
    const p = IdParam.safeParse((req as any).params);
    if (!p.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    try {
      const id = Number(p.data.id);

      const [rows]: any = await db.query(
        `SELECT listado_base64
           FROM convocatorias_historico
          WHERE id = ?
          LIMIT 1`,
        [id]
      );

      if (!rows?.length) return reply.code(404).send({ ok: false, message: "No encontrado" });

      const pure = stripDataUrlPrefix(String(rows[0].listado_base64 || ""));
      const buf = Buffer.from(pure, "base64");

      reply.header("Content-Type", "application/pdf");
      reply.header("Content-Disposition", `inline; filename="convocatoria_${id}.pdf"`);
      return reply.send(buf);
    } catch (e: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al generar PDF",
        error: e?.message,
      });
    }
  });

  // OBTENER POR ID (rol 1 y 2)  ✅ (al final para no capturar /ver/:id)
  app.get("/:id", { preHandler: canRead }, async (req, reply) => {
    const p = IdParam.safeParse((req as any).params);
    if (!p.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    try {
      const id = Number(p.data.id);

      const [rows]: any = await db.query(
        `SELECT *
           FROM convocatorias_historico
          WHERE id = ?
          LIMIT 1`,
        [id]
      );

      if (!rows?.length) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, item: rows[0] });
    } catch (e: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al obtener registro",
        error: e?.message,
      });
    }
  });

  // Crear registro (rol 1 y 2)
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

      const sql = `
        INSERT INTO convocatorias_historico
          (evento_id, convocatoria_id, fecha_generacion, listado_base64, generado_por)
        VALUES (?, ?, ${fechaMySQL ? "?" : "NOW()"}, ?, NULL)
      `;

      const params = fechaMySQL
        ? [evento_id, convocatoria_id, fechaMySQL, pure]
        : [evento_id, convocatoria_id, pure];

      const [result]: any = await db.query(sql, params);

      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        evento_id,
        convocatoria_id,
        fecha_generacion: fechaMySQL ?? new Date().toISOString(),
      });
    } catch (e: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al crear registro",
        error: e?.message,
      });
    }
  });
}
