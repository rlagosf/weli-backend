// src/routers/noticias_public.ts
import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { z, ZodError } from "zod";
import { getDb } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Estado noticias:
 * 1 = Borrador
 * 2 = Publicada
 * 3 = Archivada
 */
const ESTADO_BORRADOR_ID = 1;
const ESTADO_PUBLICADA_ID = 2;
const ESTADO_ARCHIVADA_ID = 3;

const ACADEMIA_HEADER = "x-academia-id";

type ReqUser = {
  rol_id?: number;
  academia_id?: number | null;
};

const IdParam = z.object({ id: z.coerce.number().int().positive() });

const CreateSchema = z
  .object({
    slug: z.string().trim().min(1).max(120),
    titulo: z.string().trim().min(1).max(200),
    resumen: z.string().trim().min(1).max(500),
    contenido: z.string().trim().min(1),

    estado_noticia_id: z.coerce.number().int().optional(), // 1/2/3
    published_at: z.string().optional().nullable(),

    is_popup: z.coerce.number().int().optional().default(0), // 0/1
    popup_start_at: z.string().optional().nullable(),
    popup_end_at: z.string().optional().nullable(),

    pinned: z.coerce.number().int().optional().default(0), // 0/1
    pinned_order: z.coerce.number().int().optional().nullable(),

    imagen_mime: z.string().trim().optional().nullable(),
    imagen_base64: z.string().trim().optional().nullable(),
    imagen_bytes: z.coerce.number().int().optional().nullable(),
  })
  .strict();

const UpdateSchema = CreateSchema.partial().strict();

function nowSql() {
  return new Date().toISOString().slice(0, 19).replace("T", " ");
}

/**
 * ✅ Scope multi-academia:
 * - rol 1/2: academia desde token (req.user.academia_id)
 * - rol 3: academia desde header x-academia-id
 */
function getAcademiaScope(req: FastifyRequest, reply: FastifyReply): number | null {
  const user = (req as any).user as ReqUser | undefined;
  const rol = Number(user?.rol_id ?? 0);

  if (rol === 1 || rol === 2) {
    const a = Number(user?.academia_id ?? 0);
    if (!Number.isFinite(a) || a <= 0) {
      reply.code(403).send({ ok: false, message: "Academia no asignada al usuario." });
      return null;
    }
    return a;
  }

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

/**
 * ✅ Academia para público (landing):
 * - usa x-academia-id (obligatorio para no mezclar tenants)
 */
function getAcademiaScopePublic(req: FastifyRequest, reply: FastifyReply): number | null {
  const raw = (req.headers as any)?.[ACADEMIA_HEADER];
  const v = Array.isArray(raw) ? raw[0] : raw;
  const a = Number(v);
  if (!Number.isFinite(a) || a <= 0) {
    reply.code(400).send({ ok: false, message: "Debes indicar x-academia-id." });
    return null;
  }
  return a;
}

export async function noticiasPublicRoutes(app: FastifyInstance) {
  const db = getDb();

  // 🔐 canRead/canWrite (roles 1/2/3)
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 2, 3])];

  /**
   * ✅ LECTURA PÚBLICA (LANDING) POR ACADEMIA
   * GET /api/noticias -> { popup, cards }
   * Requiere x-academia-id
   */
  app.get("/", async (req: FastifyRequest, reply: FastifyReply) => {
    const academiaId = getAcademiaScopePublic(req, reply);
    if (!academiaId) return;

    try {
      // Popup: publicada + is_popup=1 y ventana válida si existe
      const [popupRows]: any = await db.query(
        `
        SELECT id, academia_id, slug, titulo, resumen, published_at
        FROM noticias
        WHERE academia_id = ?
          AND estado_noticia_id = ?
          AND is_popup = 1
          AND (popup_start_at IS NULL OR popup_start_at <= NOW())
          AND (popup_end_at   IS NULL OR popup_end_at   >= NOW())
        ORDER BY published_at DESC, id DESC
        LIMIT 1
        `,
        [academiaId, ESTADO_PUBLICADA_ID]
      );

      const popup = popupRows?.[0] ?? null;
      const popupId = popup?.id ?? null;

      // Cards: publicadas, excluye popup, con pinned
      const [cards]: any = await db.query(
        `
        SELECT id, academia_id, slug, titulo, resumen, published_at
        FROM noticias
        WHERE academia_id = ?
          AND estado_noticia_id = ?
          AND (? IS NULL OR id <> ?)
        ORDER BY
          pinned DESC,
          COALESCE(pinned_order, 999999) ASC,
          published_at DESC,
          id DESC
        LIMIT 6
        `,
        [academiaId, ESTADO_PUBLICADA_ID, popupId, popupId]
      );

      reply.header("Cache-Control", "public, max-age=60");
      return reply.send({ ok: true, popup, cards: cards ?? [] });
    } catch (err: any) {
      req.log.error({ err }, "[noticias_public] Error GET /api/noticias");
      return reply.code(500).send({ ok: false, message: "Error interno (noticias)" });
    }
  });

  /**
   * ✅ LECTURA PÚBLICA (LANDING) POR ACADEMIA
   * GET /api/noticias/:id -> detalle (solo publicadas)
   * Requiere x-academia-id (anti-leak entre tenants)
   */
  app.get("/:id", async (req: FastifyRequest, reply: FastifyReply) => {
    const academiaId = getAcademiaScopePublic(req, reply);
    if (!academiaId) return;

    const pid = IdParam.safeParse(req.params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });
    const id = pid.data.id;

    try {
      const [rows]: any = await db.query(
        `
        SELECT id, academia_id, slug, titulo, resumen, contenido, published_at,
               imagen_mime, imagen_base64, imagen_bytes
        FROM noticias
        WHERE id = ?
          AND academia_id = ?
          AND estado_noticia_id = ?
        LIMIT 1
        `,
        [id, academiaId, ESTADO_PUBLICADA_ID]
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
  // 🔐 MUTACIONES (roles 1/2/3) + scope academia
  // ─────────────────────────────────────────────────────────────

  // POST /api/noticias  (crear)
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const academiaId = getAcademiaScope(req, reply);
    if (!academiaId) return;

    let body: z.infer<typeof CreateSchema>;
    try {
      body = CreateSchema.parse(req.body);
    } catch (e) {
      if (e instanceof ZodError) {
        return reply.code(400).send({ ok: false, message: "Payload inválido", errors: e.flatten() });
      }
      throw e;
    }

    // normaliza slug (evita duplicados por caso/espacios)
    const slug = body.slug.trim().toLowerCase();

    const estado = [ESTADO_BORRADOR_ID, ESTADO_PUBLICADA_ID, ESTADO_ARCHIVADA_ID].includes(
      Number(body.estado_noticia_id)
    )
      ? Number(body.estado_noticia_id)
      : ESTADO_BORRADOR_ID;

    const publishedAt =
      estado === ESTADO_PUBLICADA_ID ? (body.published_at ? body.published_at : nowSql()) : null;

    try {
      const [result]: any = await db.query(
        `
        INSERT INTO noticias (
          academia_id,
          slug, titulo, resumen, contenido,
          estado_noticia_id, published_at,
          is_popup, popup_start_at, popup_end_at,
          pinned, pinned_order,
          imagen_mime, imagen_base64, imagen_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          academiaId,
          slug,
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
      if (err?.errno === 1062) {
        return reply.code(409).send({ ok: false, message: "Duplicado: slug ya existe" });
      }
      req.log.error({ err }, "[noticias_public] Error POST /api/noticias");
      return reply.code(500).send({ ok: false, message: "Error al crear noticia" });
    }
  });

  // PUT /api/noticias/:id  (editar)
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const academiaId = getAcademiaScope(req, reply);
    if (!academiaId) return;

    const pid = IdParam.safeParse(req.params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });
    const id = pid.data.id;

    let body: any;
    try {
      body = UpdateSchema.parse(req.body);
    } catch (e) {
      if (e instanceof ZodError) {
        return reply.code(400).send({ ok: false, message: "Payload inválido", errors: e.flatten() });
      }
      throw e;
    }

    if (Object.keys(body).length === 0) {
      return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
    }

    if (body.slug !== undefined) body.slug = String(body.slug).trim().toLowerCase();

    if (body.estado_noticia_id !== undefined) {
      const n = Number(body.estado_noticia_id);
      if (![ESTADO_BORRADOR_ID, ESTADO_PUBLICADA_ID, ESTADO_ARCHIVADA_ID].includes(n)) {
        return reply.code(400).send({ ok: false, message: "estado_noticia_id inválido" });
      }
      body.estado_noticia_id = n;

      if (n === ESTADO_PUBLICADA_ID && body.published_at == null) body.published_at = nowSql();
      if (n !== ESTADO_PUBLICADA_ID) body.published_at = null;
    }

    if (body.is_popup !== undefined) body.is_popup = Number(body.is_popup) ? 1 : 0;
    if (body.pinned !== undefined) body.pinned = Number(body.pinned) ? 1 : 0;

    // 🚫 blindaje: nunca permitir cambiar academia_id desde cliente
    delete body.academia_id;

    try {
      const [res]: any = await db.query(
        "UPDATE noticias SET ? WHERE id = ? AND academia_id = ?",
        [body, id, academiaId]
      );
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

  // PATCH /api/noticias/:id/estado
  app.patch("/:id/estado", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const academiaId = getAcademiaScope(req, reply);
    if (!academiaId) return;

    const pid = IdParam.safeParse(req.params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });
    const id = pid.data.id;

    const parsed = z.object({ estado_noticia_id: z.coerce.number().int() }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "Payload inválido" });

    const estado_noticia_id = parsed.data.estado_noticia_id;

    if (![ESTADO_BORRADOR_ID, ESTADO_PUBLICADA_ID, ESTADO_ARCHIVADA_ID].includes(estado_noticia_id)) {
      return reply.code(400).send({ ok: false, message: "estado_noticia_id inválido" });
    }

    const published_at = estado_noticia_id === ESTADO_PUBLICADA_ID ? nowSql() : null;

    try {
      const [res]: any = await db.query(
        "UPDATE noticias SET estado_noticia_id = ?, published_at = ? WHERE id = ? AND academia_id = ?",
        [estado_noticia_id, published_at, id, academiaId]
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
    const academiaId = getAcademiaScope(req, reply);
    if (!academiaId) return;

    const pid = IdParam.safeParse(req.params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });
    const id = pid.data.id;

    const parsed = z
      .object({
        is_popup: z.coerce.number().int().optional(),
        popup_start_at: z.string().nullable().optional(),
        popup_end_at: z.string().nullable().optional(),
      })
      .strict()
      .safeParse(req.body);

    if (!parsed.success) return reply.code(400).send({ ok: false, message: "Payload inválido" });

    try {
      const payload: any = {};
      if (parsed.data.is_popup !== undefined) payload.is_popup = Number(parsed.data.is_popup) ? 1 : 0;
      if (parsed.data.popup_start_at !== undefined) payload.popup_start_at = parsed.data.popup_start_at;
      if (parsed.data.popup_end_at !== undefined) payload.popup_end_at = parsed.data.popup_end_at;

      if (Object.keys(payload).length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const [res]: any = await db.query(
        "UPDATE noticias SET ? WHERE id = ? AND academia_id = ?",
        [payload, id, academiaId]
      );
      if (res.affectedRows === 0) return reply.code(404).send({ ok: false, message: "Not found" });

      return reply.send({ ok: true, updated: { id, ...payload } });
    } catch (err: any) {
      req.log.error({ err }, "[noticias_public] Error PATCH /popup");
      return reply.code(500).send({ ok: false, message: "Error al actualizar popup" });
    }
  });

  // PATCH /api/noticias/:id/pinned
  app.patch("/:id/pinned", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const academiaId = getAcademiaScope(req, reply);
    if (!academiaId) return;

    const pid = IdParam.safeParse(req.params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });
    const id = pid.data.id;

    const parsed = z
      .object({
        pinned: z.coerce.number().int().optional(),
        pinned_order: z.coerce.number().int().nullable().optional(),
      })
      .strict()
      .safeParse(req.body);

    if (!parsed.success) return reply.code(400).send({ ok: false, message: "Payload inválido" });

    try {
      const payload: any = {};
      if (parsed.data.pinned !== undefined) payload.pinned = Number(parsed.data.pinned) ? 1 : 0;
      if (parsed.data.pinned_order !== undefined) payload.pinned_order = parsed.data.pinned_order;

      if (Object.keys(payload).length === 0) {
        return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
      }

      const [res]: any = await db.query(
        "UPDATE noticias SET ? WHERE id = ? AND academia_id = ?",
        [payload, id, academiaId]
      );
      if (res.affectedRows === 0) return reply.code(404).send({ ok: false, message: "Not found" });

      return reply.send({ ok: true, updated: { id, ...payload } });
    } catch (err: any) {
      req.log.error({ err }, "[noticias_public] Error PATCH /pinned");
      return reply.code(500).send({ ok: false, message: "Error al actualizar pinned" });
    }
  });

  // DELETE /api/noticias/:id
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const academiaId = getAcademiaScope(req, reply);
    if (!academiaId) return;

    const pid = IdParam.safeParse(req.params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });
    const id = pid.data.id;

    try {
      const [res]: any = await db.query("DELETE FROM noticias WHERE id = ? AND academia_id = ?", [id, academiaId]);
      if (res.affectedRows === 0) return reply.code(404).send({ ok: false, message: "Not found" });
      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      req.log.error({ err }, "[noticias_public] Error DELETE /api/noticias/:id");
      return reply.code(500).send({ ok: false, message: "Error al eliminar noticia" });
    }
  });

  // (Opcional) endpoint privado futuro, por ejemplo: listar borradores por academia
  // app.get("/admin/list", { preHandler: canRead }, async (...) => ...)
}
