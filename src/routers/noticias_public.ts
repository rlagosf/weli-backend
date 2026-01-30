// src/routers/noticias_public.ts
import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { z } from "zod";
import { getDb } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Estado noticias (tu regla real):
 * 1 = Borrador
 * 2 = Publicada
 * 3 = Archivada
 */
const ESTADO_BORRADOR_ID = 1;
const ESTADO_PUBLICADA_ID = 2;
const ESTADO_ARCHIVADA_ID = 3;

const IdParam = z.object({ id: z.coerce.number().int().positive() });

const CreateSchema = z
  .object({
    slug: z.string().trim().min(1).max(120),
    titulo: z.string().trim().min(1).max(200),
    resumen: z.string().trim().min(1).max(500),
    contenido: z.string().trim().min(1),

    // opcionales de publicación
    estado_noticia_id: z.coerce.number().int().optional(), // 1/2/3
    published_at: z.string().optional().nullable(),

    // flags
    is_popup: z.coerce.number().int().optional().default(0), // 0/1
    popup_start_at: z.string().optional().nullable(),
    popup_end_at: z.string().optional().nullable(),

    pinned: z.coerce.number().int().optional().default(0), // 0/1
    pinned_order: z.coerce.number().int().optional().nullable(),

    // imagen opcional (si ya la estás guardando en noticias)
    imagen_mime: z.string().trim().optional().nullable(),
    imagen_base64: z.string().trim().optional().nullable(),
    imagen_bytes: z.coerce.number().int().optional().nullable(),
  })
  .strict();

const UpdateSchema = CreateSchema.partial().strict();

function nowSql() {
  return new Date().toISOString().slice(0, 19).replace("T", " ");
}

export async function noticiasPublicRoutes(app: FastifyInstance) {
  const db = getDb();

  // 🔐 para mutaciones (rol 1 y 2 full)
  const canWrite = [requireAuth, requireRoles([1, 2])];

  /**
   * ✅ LECTURA PÚBLICA (LANDING)
   * GET /api/noticias -> { popup, cards }
   */
  app.get("/", async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      // Popup: publicada + is_popup=1 y ventana válida si existe
      const [popupRows]: any = await db.query(
        `
        SELECT id, slug, titulo, resumen, published_at
        FROM noticias
        WHERE estado_noticia_id = ?
          AND is_popup = 1
          AND (popup_start_at IS NULL OR popup_start_at <= NOW())
          AND (popup_end_at   IS NULL OR popup_end_at   >= NOW())
        ORDER BY published_at DESC, id DESC
        LIMIT 1
        `,
        [ESTADO_PUBLICADA_ID]
      );

      const popup = popupRows?.[0] ?? null;
      const popupId = popup?.id ?? null;

      // Cards: publicadas, excluye popup, con pinned
      const [cards]: any = await db.query(
        `
        SELECT id, slug, titulo, resumen, published_at
        FROM noticias
        WHERE estado_noticia_id = ?
          AND (? IS NULL OR id <> ?)
        ORDER BY
          pinned DESC,
          COALESCE(pinned_order, 999999) ASC,
          published_at DESC,
          id DESC
        LIMIT 6
        `,
        [ESTADO_PUBLICADA_ID, popupId, popupId]
      );

      // 👇 cache suave para landing (si quieres puedes ajustar)
      reply.header("Cache-Control", "public, max-age=60");

      return reply.send({ ok: true, popup, cards: cards ?? [] });
    } catch (err: any) {
      req.log.error({ err }, "[noticias_public] Error GET /api/noticias");
      return reply.code(500).send({ ok: false, message: "Error interno (noticias)" });
    }
  });

  /**
   * ✅ LECTURA PÚBLICA (LANDING)
   * GET /api/noticias/:id -> detalle (solo publicadas)
   */
  app.get("/:id", async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = IdParam.parse(req.params);

    try {
      const [rows]: any = await db.query(
        `
        SELECT id, slug, titulo, resumen, contenido, published_at,
               imagen_mime, imagen_base64, imagen_bytes
        FROM noticias
        WHERE id = ?
          AND estado_noticia_id = ?
        LIMIT 1
        `,
        [id, ESTADO_PUBLICADA_ID]
      );

      const item = rows?.[0];
      if (!item) return reply.code(404).send({ ok: false, message: "Not found" });

      reply.header("Cache-Control", "public, max-age=60");
      return reply.send({ ok: true, item });
    } catch (err: any) {
      req.log.error({ err }, "[noticias_public] Error GET /api/noticias/:id");
      return reply.code(500).send({ ok: false, message: "Error interno (noticia)" });
    }
  });

  // ─────────────────────────────────────────────────────────────
  // 🔐 MUTACIONES (roles 1/2 FULL)
  // ─────────────────────────────────────────────────────────────

  // POST /api/noticias  (crear)
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const body = CreateSchema.parse(req.body);

    const estado = [ESTADO_BORRADOR_ID, ESTADO_PUBLICADA_ID, ESTADO_ARCHIVADA_ID].includes(
      Number(body.estado_noticia_id)
    )
      ? Number(body.estado_noticia_id)
      : ESTADO_BORRADOR_ID;

    // published_at: si publicas y no mandas, lo seteamos ahora
    const publishedAt =
      estado === ESTADO_PUBLICADA_ID
        ? (body.published_at ? body.published_at : nowSql())
        : null;

    try {
      const [result]: any = await db.query(
        `
        INSERT INTO noticias (
          slug, titulo, resumen, contenido,
          estado_noticia_id, published_at,
          is_popup, popup_start_at, popup_end_at,
          pinned, pinned_order,
          imagen_mime, imagen_base64, imagen_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          body.slug,
          body.titulo,
          body.resumen,
          body.contenido,
          estado,
          publishedAt,
          Number(body.is_popup) ? 1 : 0,
          body.popup_start_at ?? null,
          body.popup_end_at ?? null,
          Number(body.pinned) ? 1 : 0,
          body.pinned_order ?? null,
          body.imagen_mime ?? null,
          body.imagen_base64 ?? null,
          body.imagen_bytes ?? null,
        ]
      );

      return reply.code(201).send({ ok: true, id: result.insertId });
    } catch (err: any) {
      // duplicado slug probablemente
      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "Duplicado: slug ya existe" });
      }
      req.log.error({ err }, "[noticias_public] Error POST /api/noticias");
      return reply.code(500).send({ ok: false, message: "Error al crear noticia" });
    }
  });

  // PUT /api/noticias/:id  (editar)
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = IdParam.parse(req.params);
    const body = UpdateSchema.parse(req.body);

    if (Object.keys(body).length === 0) {
      return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
    }

    // estado válido si viene
    if (body.estado_noticia_id !== undefined) {
      const n = Number(body.estado_noticia_id);
      if (![ESTADO_BORRADOR_ID, ESTADO_PUBLICADA_ID, ESTADO_ARCHIVADA_ID].includes(n)) {
        return reply.code(400).send({ ok: false, message: "estado_noticia_id inválido" });
      }
      body.estado_noticia_id = n;
      // si cambias a publicada y no mandas published_at -> ahora
      if (n === ESTADO_PUBLICADA_ID && body.published_at == null) {
        (body as any).published_at = nowSql();
      }
      // si sales de publicada -> published_at null (opcional, si quieres conservarlo, quita esto)
      if (n !== ESTADO_PUBLICADA_ID) {
        (body as any).published_at = null;
      }
    }

    // flags numéricos
    if (body.is_popup !== undefined) (body as any).is_popup = Number(body.is_popup) ? 1 : 0;
    if (body.pinned !== undefined) (body as any).pinned = Number(body.pinned) ? 1 : 0;

    try {
      const [res]: any = await db.query("UPDATE noticias SET ? WHERE id = ?", [body, id]);
      if (res.affectedRows === 0) return reply.code(404).send({ ok: false, message: "Not found" });
      return reply.send({ ok: true, updated: { id, ...body } });
    } catch (err: any) {
      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "Duplicado: slug ya existe" });
      }
      req.log.error({ err }, "[noticias_public] Error PUT /api/noticias/:id");
      return reply.code(500).send({ ok: false, message: "Error al actualizar noticia" });
    }
  });

  // PATCH /api/noticias/:id/estado  (cambiar estado)
  app.patch("/:id/estado", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = IdParam.parse(req.params);
    const { estado_noticia_id } = z
      .object({ estado_noticia_id: z.coerce.number().int() })
      .parse(req.body);

    if (![ESTADO_BORRADOR_ID, ESTADO_PUBLICADA_ID, ESTADO_ARCHIVADA_ID].includes(estado_noticia_id)) {
      return reply.code(400).send({ ok: false, message: "estado_noticia_id inválido" });
    }

    const published_at = estado_noticia_id === ESTADO_PUBLICADA_ID ? nowSql() : null;

    try {
      const [res]: any = await db.query(
        "UPDATE noticias SET estado_noticia_id = ?, published_at = ? WHERE id = ?",
        [estado_noticia_id, published_at, id]
      );
      if (res.affectedRows === 0) return reply.code(404).send({ ok: false, message: "Not found" });
      return reply.send({ ok: true, id, estado_noticia_id, published_at });
    } catch (err: any) {
      req.log.error({ err }, "[noticias_public] Error PATCH /estado");
      return reply.code(500).send({ ok: false, message: "Error al cambiar estado" });
    }
  });

  // PATCH /api/noticias/:id/popup
  app.patch("/:id/popup", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = IdParam.parse(req.params);
    const body = z
      .object({
        is_popup: z.coerce.number().int().optional(),
        popup_start_at: z.string().nullable().optional(),
        popup_end_at: z.string().nullable().optional(),
      })
      .strict()
      .parse(req.body);

    try {
      const payload: any = {};
      if (body.is_popup !== undefined) payload.is_popup = Number(body.is_popup) ? 1 : 0;
      if (body.popup_start_at !== undefined) payload.popup_start_at = body.popup_start_at;
      if (body.popup_end_at !== undefined) payload.popup_end_at = body.popup_end_at;

      if (Object.keys(payload).length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const [res]: any = await db.query("UPDATE noticias SET ? WHERE id = ?", [payload, id]);
      if (res.affectedRows === 0) return reply.code(404).send({ ok: false, message: "Not found" });

      return reply.send({ ok: true, updated: { id, ...payload } });
    } catch (err: any) {
      req.log.error({ err }, "[noticias_public] Error PATCH /popup");
      return reply.code(500).send({ ok: false, message: "Error al actualizar popup" });
    }
  });

  // PATCH /api/noticias/:id/pinned
  app.patch("/:id/pinned", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = IdParam.parse(req.params);
    const body = z
      .object({
        pinned: z.coerce.number().int().optional(),
        pinned_order: z.coerce.number().int().nullable().optional(),
      })
      .strict()
      .parse(req.body);

    try {
      const payload: any = {};
      if (body.pinned !== undefined) payload.pinned = Number(body.pinned) ? 1 : 0;
      if (body.pinned_order !== undefined) payload.pinned_order = body.pinned_order;

      if (Object.keys(payload).length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const [res]: any = await db.query("UPDATE noticias SET ? WHERE id = ?", [payload, id]);
      if (res.affectedRows === 0) return reply.code(404).send({ ok: false, message: "Not found" });

      return reply.send({ ok: true, updated: { id, ...payload } });
    } catch (err: any) {
      req.log.error({ err }, "[noticias_public] Error PATCH /pinned");
      return reply.code(500).send({ ok: false, message: "Error al actualizar pinned" });
    }
  });

  // DELETE /api/noticias/:id  (borrar)
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = IdParam.parse(req.params);

    try {
      const [res]: any = await db.query("DELETE FROM noticias WHERE id = ?", [id]);
      if (res.affectedRows === 0) return reply.code(404).send({ ok: false, message: "Not found" });
      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      req.log.error({ err }, "[noticias_public] Error DELETE /api/noticias/:id");
      return reply.code(500).send({ ok: false, message: "Error al eliminar noticia" });
    }
  });
}
