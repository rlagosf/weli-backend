import type { FastifyInstance, FastifyPluginOptions } from "fastify";
import { z } from "zod";
import { getDb } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

const ACADEMIA_HEADER = "x-academia-id";

// ✅ Bool robusto (evita Boolean("false") === true)
const BoolLike = z.preprocess((v) => {
  if (v === undefined || v === null) return undefined;
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v === 1;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (["true", "1", "yes", "y", "on"].includes(s)) return true;
    if (["false", "0", "no", "n", "off"].includes(s)) return false;
  }
  return v;
}, z.boolean());

const EstadoId = z.coerce.number().int().positive();

const ListQuerySchema = z.object({
  mode: z.enum(["panel", "landing"]).optional(),

  q: z.string().optional(),
  estado_noticia_id: EstadoId.optional(),
  include_archived: BoolLike.optional(),

  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

const IdSchema = z.object({ id: z.coerce.number().int().positive() });

function isIsoDatetime(s: string) {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(\.\d{1,6})?(Z|[+\-]\d{2}:\d{2})?$/.test(s);
}
function isMysqlDatetime(s: string) {
  return /^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}$/.test(s);
}

const DateTimeLike = z
  .string()
  .trim()
  .refine((s) => isIsoDatetime(s) || isMysqlDatetime(s), { message: "INVALID_DATETIME" });

function toMysqlDatetime(val: string) {
  const s = String(val).trim();
  if (!s) return null;
  if (isMysqlDatetime(s)) return s;
  if (s.includes("T")) return s.replace("T", " ").slice(0, 19);
  return s;
}

function trimOrNull(v?: string | null) {
  if (v == null) return null;
  const s = String(v).trim();
  return s ? s : null;
}

function normalizePopup(p: { is_popup?: any; popup_start_at?: any; popup_end_at?: any }) {
  const is_popup = !!p.is_popup;
  if (!is_popup) return { is_popup: 0, popup_start_at: null, popup_end_at: null };

  return {
    is_popup: 1,
    popup_start_at: trimOrNull(p.popup_start_at) ? toMysqlDatetime(String(p.popup_start_at)) : null,
    popup_end_at: trimOrNull(p.popup_end_at) ? toMysqlDatetime(String(p.popup_end_at)) : null,
  };
}

function normalizePinned(p: { pinned?: any; pinned_order?: any }) {
  const pinned = !!p.pinned;
  if (!pinned) return { pinned: 0, pinned_order: null };
  const n = Number(p.pinned_order ?? 0);
  return { pinned: 1, pinned_order: Number.isFinite(n) ? n : 0 };
}

async function ensureEstadoExists(db: any, estadoId: number) {
  const [[row]] = (await db.query(`SELECT id FROM estado_noticias WHERE id = ? LIMIT 1`, [estadoId])) as any;
  return !!row;
}

async function getEstadoIdByName(db: any, name: string) {
  const [[row]] = (await db.query(
    `SELECT id FROM estado_noticias WHERE LOWER(nombre) = LOWER(?) LIMIT 1`,
    [name]
  )) as any;
  return row?.id ? Number(row.id) : null;
}

/** ✅ Resuelve tenant efectivo según rol */
function resolveAcademiaIdOrFail(req: any, reply: any): number | null {
  const auth = req.auth as { type: "user"; rol_id?: number; academia_id?: number; user_id?: number } | undefined;
  const role = Number(auth?.rol_id ?? 0);

  // Rol 1/2: academia_id del token OBLIGATORIO
  if (role === 1 || role === 2) {
    const id = Number(auth?.academia_id ?? 0);
    if (!Number.isFinite(id) || id <= 0) {
      reply.code(400).send({ ok: false, message: "ACADEMIA_ID_REQUIRED" });
      return null;
    }
    return id;
  }

  // Rol 3: header x-academia-id (solo obligatorio para mutaciones / si se quiere filtrar)
  if (role === 3) {
    const raw = req.headers?.[ACADEMIA_HEADER] ?? req.headers?.[ACADEMIA_HEADER.toLowerCase()];
    const id = Number(raw ?? 0);
    if (Number.isFinite(id) && id > 0) return id;
    return 0; // 0 = sin filtro (ver todas)
  }

  reply.code(403).send({ ok: false, message: "FORBIDDEN" });
  return null;
}

const BaseSchema = z.object({
  slug: z.string().min(1).max(160),
  titulo: z.string().min(1).max(180),
  resumen: z.string().max(280).nullable().optional(),
  contenido: z.string().nullable().optional(),

  estado_noticia_id: EstadoId.default(1),

  is_popup: BoolLike.optional(),
  popup_start_at: DateTimeLike.nullable().optional(),
  popup_end_at: DateTimeLike.nullable().optional(),

  pinned: BoolLike.optional(),
  pinned_order: z.coerce.number().int().nullable().optional(),
});

const CreateSchema = BaseSchema.extend({
  imagen_mime: z.string().max(40).nullable().optional(),
  imagen_base64: z.string().nullable().optional(),
  imagen_bytes: z.coerce.number().int().nonnegative().nullable().optional(),
});

const UpdateSchema = BaseSchema.partial().extend({
  published_at: DateTimeLike.nullable().optional(),
  imagen_mime: z.string().max(40).nullable().optional(),
  imagen_base64: z.string().nullable().optional(),
  imagen_bytes: z.coerce.number().int().nonnegative().nullable().optional(),
});

export default async function admin_noticias(app: FastifyInstance, _opts: FastifyPluginOptions) {
  // ✅ Panel protegido: roles 1,2,3
  const onlyPanel = [requireAuth, requireRoles([1, 2, 3])];

  /**
   * ✅ GET /api/admin-noticias
   * - mode=landing: público (publicadas)
   * - mode=panel (default): protegido (rol 1,2,3)
   *
   * Panel:
   * - rol 1/2 => filtra por academia_id del token (obligatorio)
   * - rol 3 => si manda x-academia-id filtra; si no, ve todas
   */
  app.get("/", async (req: any, reply) => {
    const parsed = ListQuerySchema.safeParse(req.query);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "BAD_REQUEST" });

    const { mode, q, estado_noticia_id, include_archived, limit, offset } = parsed.data;

    // 🔐 Panel: proteger (landing queda público)
    if (mode !== "landing") {
      for (const guard of onlyPanel) {
        await guard(req, reply);
        if (reply.sent) return;
      }
    }

    const db = getDb();

    const archivadaId =
      (await getEstadoIdByName(db, "Archivada")) ??
      (await getEstadoIdByName(db, "Archivado")) ??
      3;

    if (estado_noticia_id !== undefined) {
      const ok = await ensureEstadoExists(db, estado_noticia_id);
      if (!ok) return reply.code(400).send({ ok: false, message: "ESTADO_NOTICIA_INVALID" });
    }

    // ===== LANDING MODE ===== (público, global)
    if (mode === "landing") {
      const publicadaId =
        (await getEstadoIdByName(db, "Publicada")) ??
        (await getEstadoIdByName(db, "Publicado")) ??
        2;

      const [popupRows] = (await db.query(
        `
        SELECT
          n.id, n.slug, n.titulo, n.resumen,
          n.imagen_mime, n.imagen_bytes,
          n.estado_noticia_id,
          n.published_at,
          n.is_popup, n.popup_start_at, n.popup_end_at
        FROM noticias n
        WHERE n.estado_noticia_id = ?
          AND n.is_popup = 1
          AND (n.popup_start_at IS NULL OR n.popup_start_at <= NOW())
          AND (n.popup_end_at   IS NULL OR n.popup_end_at   >= NOW())
        ORDER BY n.published_at DESC, n.updated_at DESC
        LIMIT 1
        `,
        [publicadaId]
      )) as any;

      const [cardRows] = (await db.query(
        `
        SELECT
          n.id, n.slug, n.titulo, n.resumen,
          n.imagen_mime, n.imagen_bytes,
          n.estado_noticia_id,
          n.published_at,
          n.pinned, n.pinned_order
        FROM noticias n
        WHERE n.estado_noticia_id = ?
          AND n.is_popup = 0
        ORDER BY n.pinned DESC,
                 n.pinned_order IS NULL, n.pinned_order ASC,
                 n.published_at DESC, n.updated_at DESC
        LIMIT 6
        `,
        [publicadaId]
      )) as any;

      return reply.send({
        ok: true,
        popup: popupRows?.[0] ?? null,
        cards: cardRows ?? [],
      });
    }

    // ===== PANEL MODE =====
    const academiaId = resolveAcademiaIdOrFail(req, reply);
    if (academiaId == null) return;

    const where: string[] = [];
    const params: any[] = [];

    // tenant filter:
    // - rol 1/2 => academiaId > 0 (obligatorio)
    // - rol 3 => academiaId puede ser 0 (sin filtro, ve todo)
    if (academiaId > 0) {
      where.push("n.academia_id = ?");
      params.push(academiaId);
    }

    if (!include_archived && estado_noticia_id === undefined) {
      where.push("n.estado_noticia_id <> ?");
      params.push(archivadaId);
    }

    if (estado_noticia_id !== undefined) {
      where.push("n.estado_noticia_id = ?");
      params.push(estado_noticia_id);
    }

    if (q && q.trim()) {
      const like = `%${q.trim()}%`;
      where.push("(n.titulo LIKE ? OR n.slug LIKE ?)");
      params.push(like, like);
    }

    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const [rows] = (await db.query(
      `
      SELECT
        n.id, n.slug, n.titulo, n.resumen,
        n.imagen_mime, n.imagen_bytes,
        n.estado_noticia_id,
        en.nombre AS estado_nombre,
        n.published_at,
        n.is_popup, n.popup_start_at, n.popup_end_at,
        n.pinned, n.pinned_order,
        n.created_at, n.updated_at,
        n.academia_id
      FROM noticias n
      JOIN estado_noticias en ON en.id = n.estado_noticia_id
      ${whereSql}
      ORDER BY n.updated_at DESC
      LIMIT ? OFFSET ?
      `,
      [...params, limit, offset]
    )) as any;

    const [[countRow]] = (await db.query(
      `
      SELECT COUNT(*) AS total
      FROM noticias n
      ${whereSql}
      `,
      params
    )) as any;

    return reply.send({
      ok: true,
      items: rows ?? [],
      total: Number(countRow?.total ?? 0),
      limit,
      offset,
      archivada_id: archivadaId,
      academia_id: academiaId > 0 ? academiaId : null,
    });
  });

  /**
   * ✅ GET /api/admin-noticias/:id
   * 🔐 Protegido: roles 1,2,3 (tenant-aware)
   */
  app.get("/:id", { preHandler: onlyPanel }, async (req: any, reply) => {
    const parsed = IdSchema.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "BAD_REQUEST" });

    const academiaId = resolveAcademiaIdOrFail(req, reply);
    if (academiaId == null) return;

    const db = getDb();

    const where = ["n.id = ?"];
    const params: any[] = [parsed.data.id];

    if (academiaId > 0) {
      where.push("n.academia_id = ?");
      params.push(academiaId);
    }

    const [rows] = (await db.query(
      `
      SELECT
        n.*,
        en.nombre AS estado_nombre
      FROM noticias n
      JOIN estado_noticias en ON en.id = n.estado_noticia_id
      WHERE ${where.join(" AND ")}
      LIMIT 1
      `,
      params
    )) as any;

    if (!rows?.length) return reply.code(404).send({ ok: false, message: "NOT_FOUND" });
    return reply.send({ ok: true, item: rows[0] });
  });

  /**
   * ✅ POST /api/admin-noticias
   * 🔐 roles 1,2,3 (tenant-aware)
   */
  app.post("/", { preHandler: onlyPanel }, async (req: any, reply) => {
    const parsed = CreateSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "BAD_REQUEST" });

    const d = parsed.data;
    const db = getDb();

    const academiaId = resolveAcademiaIdOrFail(req, reply);
    if (academiaId == null) return;

    // Para crear, rol 3 debe seleccionar academia sí o sí
    const role = Number(req.auth?.rol_id ?? 0);
    if (role === 3 && academiaId <= 0) {
      return reply.code(400).send({ ok: false, message: "X_ACADEMIA_ID_REQUIRED" });
    }

    const okEstado = await ensureEstadoExists(db, d.estado_noticia_id);
    if (!okEstado) return reply.code(400).send({ ok: false, message: "ESTADO_NOTICIA_INVALID" });

    const popup = normalizePopup(d);
    const pin = normalizePinned(d);

    if (popup.is_popup === 1 && !popup.popup_start_at) {
      return reply.code(400).send({ ok: false, message: "POPUP_START_REQUIRED" });
    }

    if (d.imagen_base64) {
      if (!d.imagen_mime || d.imagen_bytes == null) {
        return reply.code(400).send({ ok: false, message: "IMAGE_FIELDS_INCOMPLETE" });
      }
    }

    const publicadaId =
      (await getEstadoIdByName(db, "Publicada")) ??
      (await getEstadoIdByName(db, "Publicado")) ??
      2;

    const publishedAtSql = Number(d.estado_noticia_id) === Number(publicadaId) ? "NOW()" : "NULL";

    try {
      const [res] = (await db.query(
        `
        INSERT INTO noticias
          (academia_id,
           slug, titulo, resumen, contenido,
           imagen_mime, imagen_base64, imagen_bytes,
           estado_noticia_id, published_at,
           is_popup, popup_start_at, popup_end_at,
           pinned, pinned_order,
           created_by_admin_id)
        VALUES
          (?, 
           ?, ?, ?, ?,
           ?, ?, ?,
           ?, ${publishedAtSql},
           ?, ?, ?,
           ?, ?,
           ?)
        `,
        [
          academiaId,

          d.slug.trim(),
          d.titulo.trim(),
          d.resumen ?? null,
          d.contenido ?? null,

          d.imagen_mime ?? null,
          d.imagen_base64 ?? null,
          d.imagen_bytes ?? null,

          d.estado_noticia_id,

          popup.is_popup,
          popup.popup_start_at,
          popup.popup_end_at,

          pin.pinned,
          pin.pinned_order,

          req.auth?.user_id ?? null,
        ]
      )) as any;

      return reply.code(201).send({ ok: true, id: res?.insertId });
    } catch (e: any) {
      if (String(e?.code) === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "SLUG_ALREADY_EXISTS" });
      }
      return reply.code(500).send({ ok: false, message: "SERVER_ERROR" });
    }
  });

  /**
   * ✅ PATCH /api/admin-noticias/:id
   * 🔐 roles 1,2,3 (tenant-aware)
   */
  app.patch("/:id", { preHandler: onlyPanel }, async (req: any, reply) => {
    const idParsed = IdSchema.safeParse(req.params);
    if (!idParsed.success) return reply.code(400).send({ ok: false, message: "BAD_REQUEST" });

    const bodyParsed = UpdateSchema.safeParse(req.body);
    if (!bodyParsed.success) return reply.code(400).send({ ok: false, message: "BAD_REQUEST" });

    const id = idParsed.data.id;
    const d = bodyParsed.data;
    const db = getDb();

    const academiaId = resolveAcademiaIdOrFail(req, reply);
    if (academiaId == null) return;

    // Para mutaciones, rol 3 debe seleccionar academia sí o sí
    const role = Number(req.auth?.rol_id ?? 0);
    if (role === 3 && academiaId <= 0) {
      return reply.code(400).send({ ok: false, message: "X_ACADEMIA_ID_REQUIRED" });
    }

    // Cargar actual, pero restringido por tenant si corresponde
    const where0 = ["id = ?"];
    const params0: any[] = [id];
    if (academiaId > 0) {
      where0.push("academia_id = ?");
      params0.push(academiaId);
    }

    const [[current]] = (await db.query(
      `
      SELECT
        is_popup, popup_start_at, popup_end_at,
        pinned, pinned_order,
        imagen_mime, imagen_base64, imagen_bytes,
        published_at,
        academia_id
      FROM noticias
      WHERE ${where0.join(" AND ")}
      LIMIT 1
      `,
      params0
    )) as any;

    if (!current) return reply.code(404).send({ ok: false, message: "NOT_FOUND" });

    if (d.estado_noticia_id !== undefined) {
      const okEstado = await ensureEstadoExists(db, d.estado_noticia_id);
      if (!okEstado) return reply.code(400).send({ ok: false, message: "ESTADO_NOTICIA_INVALID" });
    }

    const sets: string[] = [];
    const params: any[] = [];
    const add = (col: string, val: any) => {
      sets.push(`${col} = ?`);
      params.push(val);
    };

    if (d.slug !== undefined) add("slug", d.slug.trim());
    if (d.titulo !== undefined) add("titulo", d.titulo.trim());
    if (d.resumen !== undefined) add("resumen", d.resumen ?? null);
    if (d.contenido !== undefined) add("contenido", d.contenido ?? null);

    if (d.is_popup !== undefined || d.popup_start_at !== undefined || d.popup_end_at !== undefined) {
      const popup = normalizePopup({
        is_popup: d.is_popup !== undefined ? d.is_popup : current.is_popup,
        popup_start_at: d.popup_start_at !== undefined ? d.popup_start_at : current.popup_start_at,
        popup_end_at: d.popup_end_at !== undefined ? d.popup_end_at : current.popup_end_at,
      });

      if (popup.is_popup === 1 && !popup.popup_start_at) {
        return reply.code(400).send({ ok: false, message: "POPUP_START_REQUIRED" });
      }

      add("is_popup", popup.is_popup);
      add("popup_start_at", popup.popup_start_at);
      add("popup_end_at", popup.popup_end_at);
    }

    if (d.pinned !== undefined || d.pinned_order !== undefined) {
      const pin = normalizePinned({
        pinned: d.pinned !== undefined ? d.pinned : current.pinned,
        pinned_order: d.pinned_order !== undefined ? d.pinned_order : current.pinned_order,
      });

      add("pinned", pin.pinned);
      add("pinned_order", pin.pinned_order);
    }

    const hasImgMime = Object.prototype.hasOwnProperty.call(d, "imagen_mime");
    const hasImgB64 = Object.prototype.hasOwnProperty.call(d, "imagen_base64");
    const hasImgBytes = Object.prototype.hasOwnProperty.call(d, "imagen_bytes");

    if (hasImgB64 && d.imagen_base64) {
      const mime = hasImgMime ? d.imagen_mime : current.imagen_mime;
      const bytes = hasImgBytes ? d.imagen_bytes : current.imagen_bytes;
      if (!mime || bytes == null) {
        return reply.code(400).send({ ok: false, message: "IMAGE_FIELDS_INCOMPLETE" });
      }
    }

    if (hasImgB64 && d.imagen_base64 == null) {
      add("imagen_base64", null);
      add("imagen_mime", null);
      add("imagen_bytes", null);
    } else {
      if (hasImgMime) add("imagen_mime", d.imagen_mime ?? null);
      if (hasImgB64) add("imagen_base64", d.imagen_base64 ?? null);
      if (hasImgBytes) add("imagen_bytes", d.imagen_bytes ?? null);
    }

    if (d.estado_noticia_id !== undefined) {
      add("estado_noticia_id", d.estado_noticia_id);

      const publicadaId =
        (await getEstadoIdByName(db, "Publicada")) ??
        (await getEstadoIdByName(db, "Publicado")) ??
        2;

      if (Number(d.estado_noticia_id) === Number(publicadaId)) {
        if (d.published_at) add("published_at", toMysqlDatetime(String(d.published_at)));
        else sets.push("published_at = COALESCE(published_at, NOW())");
      } else {
        sets.push("published_at = NULL");
      }
    }

    if (!sets.length) return reply.send({ ok: true });

    params.push(id);

    // Tenant enforcement en UPDATE (no update cross-tenant)
    const whereUpd = ["id = ?"];
    const paramsWhere: any[] = [id];
    if (academiaId > 0) {
      whereUpd.push("academia_id = ?");
      paramsWhere.push(academiaId);
    }

    try {
      const [res] = (await db.query(
        `
        UPDATE noticias
        SET ${sets.join(", ")}
        WHERE ${whereUpd.join(" AND ")}
        LIMIT 1
        `,
        [...params, ...paramsWhere.slice(1)] // ojo: id ya va en params; acá agregamos el resto
      )) as any;

      const affected = Number(res?.affectedRows ?? 0);
      if (affected === 0) return reply.code(404).send({ ok: false, message: "NOT_FOUND" });

      return reply.send({ ok: true });
    } catch (e: any) {
      if (String(e?.code) === "ER_DUP_ENTRY") {
        return reply.code(409).send({ ok: false, message: "SLUG_ALREADY_EXISTS" });
      }
      return reply.code(500).send({ ok: false, message: "SERVER_ERROR" });
    }
  });

  /**
   * ✅ DELETE /api/admin-noticias/:id
   * 🔐 roles 1,2,3 (tenant-aware)
   * - Soft archive
   */
  app.delete("/:id", { preHandler: onlyPanel }, async (req: any, reply) => {
    const parsed = IdSchema.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "BAD_REQUEST" });

    const db = getDb();

    const academiaId = resolveAcademiaIdOrFail(req, reply);
    if (academiaId == null) return;

    const role = Number(req.auth?.rol_id ?? 0);
    if (role === 3 && academiaId <= 0) {
      return reply.code(400).send({ ok: false, message: "X_ACADEMIA_ID_REQUIRED" });
    }

    const archivadaId =
      (await getEstadoIdByName(db, "Archivada")) ??
      (await getEstadoIdByName(db, "Archivado")) ??
      3;

    const whereDel = ["id = ?"];
    const paramsDel: any[] = [parsed.data.id];
    if (academiaId > 0) {
      whereDel.push("academia_id = ?");
      paramsDel.push(academiaId);
    }

    const [res] = (await db.query(
      `
      UPDATE noticias
      SET estado_noticia_id = ?,
          published_at = NULL,
          is_popup = 0,
          pinned = 0,
          pinned_order = NULL
      WHERE ${whereDel.join(" AND ")}
      LIMIT 1
      `,
      [archivadaId, ...paramsDel]
    )) as any;

    const affected = Number(res?.affectedRows ?? 0);
    if (affected === 0) return reply.code(404).send({ ok: false, message: "NOT_FOUND" });

    return reply.send({ ok: true });
  });
}
