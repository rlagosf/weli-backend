// src/routers/portal_apoderado.ts
import type { FastifyInstance, FastifyPluginOptions, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { getDb } from "../db";
import { requireAuth, requireApoderado } from "../middlewares/authz";

/* ──────────────────────────────────────────────────────────────
   Tipos / helpers de auth (desde middleware)
────────────────────────────────────────────────────────────── */
type ApoderadoAuth = { type: "apoderado"; rut: string; apoderado_id?: number };

function getApoderadoAuth(req: FastifyRequest, reply: FastifyReply): ApoderadoAuth | null {
  // ✅ preferido: req.auth (nuevo)
  const a = (req as any).auth;

  // 🔁 fallback por si tu middleware aún usa req.user:
  // (pero SOLO si además trae type apoderado)
  const u = (req as any).user;

  const src = a ?? u ?? null;
  const type = String(src?.type ?? "").toLowerCase();
  const rut = String(src?.rut ?? "");

  if (type !== "apoderado" || !/^\d{8}$/.test(rut)) {
    reply.code(401).send({ ok: false, message: "UNAUTHORIZED" });
    return null;
  }

  const apoderado_id =
    src?.apoderado_id != null && Number.isFinite(Number(src.apoderado_id))
      ? Number(src.apoderado_id)
      : undefined;

  return { type: "apoderado", rut, apoderado_id };
}

async function requireApoderadoPortalOk(rut: string) {
  const db = getDb();
  const [rows] = await db.query<any[]>(
    `SELECT must_change_password
       FROM apoderados_auth
      WHERE rut_apoderado = ?
      LIMIT 1`,
    [rut]
  );

  if (!rows?.length) return { ok: false as const, code: 401, message: "UNAUTHORIZED" };
  if (Number(rows[0]?.must_change_password) === 1) {
    return { ok: false as const, code: 403, message: "PASSWORD_CHANGE_REQUIRED" };
  }
  return { ok: true as const };
}

async function assertGuardOrReply(rut: string, reply: FastifyReply): Promise<boolean> {
  const guard = await requireApoderadoPortalOk(rut);
  if (!guard.ok) {
    reply.code(guard.code).send({ ok: false, message: guard.message });
    return false;
  }
  return true;
}

/* ──────────────────────────────────────────────────────────────
   Schemas
────────────────────────────────────────────────────────────── */
const RutJugadorParam = z.object({ rut: z.string().regex(/^\d{8}$/) });

const FotoBodySchema = z
  .object({
    foto_base64: z.string().trim().nullable(),
    foto_mime: z.string().trim().nullable(),
  })
  .strict();

/* ──────────────────────────────────────────────────────────────
   Utils
────────────────────────────────────────────────────────────── */
const safeNum = (v: any) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};

const hasB64 = (v: any) => {
  const s = String(v ?? "").trim();
  return s.length > 50;
};

const cleanBase64 = (raw: any) => {
  const s = String(raw ?? "").trim();
  return s
    .replace(/^data:application\/pdf;base64,/, "")
    .replace(/^data:.*;base64,/, "")
    .replace(/\s+/g, "");
};

async function assertJugadorPertenece(db: any, rutJugador: string, rutApoderado: string) {
  const [own] = await db.query(
    `SELECT 1
       FROM jugadores
      WHERE rut_jugador = ? AND rut_apoderado = ?
      LIMIT 1`,
    [rutJugador, rutApoderado]
  );
  return Boolean(own?.length);
}

/* ──────────────────────────────────────────────────────────────
   Router
────────────────────────────────────────────────────────────── */
export default async function portal_apoderado(
  app: FastifyInstance,
  _opts: FastifyPluginOptions
) {
  // 🔒 Blindaje total: token válido + debe ser apoderado (middleware)
  app.addHook("preHandler", requireAuth);
  app.addHook("preHandler", requireApoderado);

  /* ──────────────────────────────────────────────────────────────
     GET /api/portal-apoderado/me
  ────────────────────────────────────────────────────────────── */
  app.get("/me", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);
    if (!auth) return;

    if (!(await assertGuardOrReply(auth.rut, reply))) return;

    const db = getDb();
    let ap: any = null;

    // 1) Preferente: apoderados_auth (si tiene columnas)
    try {
      const [rows] = await db.query<any[]>(
        `SELECT rut_apoderado, nombre_apoderado, email, telefono
           FROM apoderados_auth
          WHERE rut_apoderado = ?
          LIMIT 1`,
        [auth.rut]
      );
      if (rows?.length) ap = rows[0];
    } catch {
      ap = ap ?? null;
    }

    // 2) Fallback: jugadores
    const needsFallback =
      !String(ap?.nombre_apoderado ?? "").trim() ||
      !String(ap?.email ?? "").trim() ||
      !String(ap?.telefono ?? "").trim();

    if (needsFallback) {
      const [jrows] = await db.query<any[]>(
        `SELECT nombre_apoderado, telefono_apoderado, email
           FROM jugadores
          WHERE rut_apoderado = ?
          ORDER BY id DESC
          LIMIT 1`,
        [auth.rut]
      );

      if (jrows?.length) {
        ap = {
          ...(ap || {}),
          rut_apoderado: ap?.rut_apoderado ?? auth.rut,
          nombre_apoderado: String(ap?.nombre_apoderado ?? "").trim()
            ? ap.nombre_apoderado
            : (jrows[0]?.nombre_apoderado ?? ""),
          email: String(ap?.email ?? "").trim() ? ap.email : (jrows[0]?.email ?? null),
          telefono: String(ap?.telefono ?? "").trim()
            ? ap.telefono
            : (jrows[0]?.telefono_apoderado ?? null),
        };
      }
    }

    return reply.send({
      ok: true,
      apoderado: {
        rut_apoderado: String(ap?.rut_apoderado ?? auth.rut),
        nombre_apoderado: String(ap?.nombre_apoderado ?? "").trim(),
        email: ap?.email ?? null,
        telefono: ap?.telefono ?? null,
      },
    });
  });

  /* ──────────────────────────────────────────────────────────────
     GET /api/portal-apoderado/mis-jugadores
  ────────────────────────────────────────────────────────────── */
  app.get("/mis-jugadores", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);
    if (!auth) return;

    if (!(await assertGuardOrReply(auth.rut, reply))) return;

    const db = getDb();

    const [rows] = await db.query<any[]>(
      `SELECT
          j.rut_jugador,
          j.nombre_jugador,
          j.estado_id,
          j.categoria_id,
          j.posicion_id,
          (j.contrato_prestacion IS NOT NULL AND j.contrato_prestacion <> '') AS tiene_contrato,
          e.nombre  AS estado_nombre,
          c.nombre  AS categoria_nombre,
          p.nombre  AS posicion_nombre
       FROM jugadores j
       LEFT JOIN estado     e ON e.id = j.estado_id
       LEFT JOIN categorias c ON c.id = j.categoria_id
       LEFT JOIN posiciones p ON p.id = j.posicion_id
       WHERE j.rut_apoderado = ?
       ORDER BY j.nombre_jugador ASC`,
      [auth.rut]
    );

    const jugadores = (rows || []).map((r) => ({
      rut_jugador: r.rut_jugador,
      nombre_jugador: r.nombre_jugador,
      estado_id: r.estado_id,
      categoria_id: r.categoria_id,
      posicion_id: r.posicion_id,
      tiene_contrato: Boolean(r.tiene_contrato),
      estado: r.estado_nombre ? { id: safeNum(r.estado_id), nombre: r.estado_nombre } : null,
      categoria: r.categoria_nombre ? { id: safeNum(r.categoria_id), nombre: r.categoria_nombre } : null,
      posicion: r.posicion_nombre ? { id: safeNum(r.posicion_id), nombre: r.posicion_nombre } : null,
    }));

    return reply.send({ ok: true, jugadores });
  });

  /* ──────────────────────────────────────────────────────────────
     GET /api/portal-apoderado/jugadores/:rut/foto
  ────────────────────────────────────────────────────────────── */
  app.get("/jugadores/:rut/foto", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);
    if (!auth) return;

    if (!(await assertGuardOrReply(auth.rut, reply))) return;

    const parsed = RutJugadorParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "BAD_REQUEST" });

    const rutJugador = parsed.data.rut;
    const db = getDb();

    const okOwn = await assertJugadorPertenece(db, rutJugador, auth.rut);
    if (!okOwn) return reply.code(403).send({ ok: false, message: "FORBIDDEN" });

    const [rows] = await db.query<any[]>(
      `SELECT foto_base64, foto_mime
         FROM jugadores
        WHERE rut_jugador = ?
        LIMIT 1`,
      [rutJugador]
    );

    const r = rows?.[0] ?? null;
    if (!r) return reply.code(404).send({ ok: false, message: "NOT_FOUND" });

    return reply.send({
      ok: true,
      foto_base64: r.foto_base64 ?? null,
      foto_mime: r.foto_mime ?? null,
    });
  });

  /* ──────────────────────────────────────────────────────────────
     PATCH /api/portal-apoderado/jugadores/:rut/foto
  ────────────────────────────────────────────────────────────── */
  app.patch("/jugadores/:rut/foto", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);
    if (!auth) return;

    if (!(await assertGuardOrReply(auth.rut, reply))) return;

    const parsed = RutJugadorParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "BAD_REQUEST" });

    const body = FotoBodySchema.safeParse(req.body);
    if (!body.success) return reply.code(400).send({ ok: false, message: "BAD_REQUEST" });

    const rutJugador = parsed.data.rut;
    const db = getDb();

    const okOwn = await assertJugadorPertenece(db, rutJugador, auth.rut);
    if (!okOwn) return reply.code(403).send({ ok: false, message: "FORBIDDEN" });

    const fotoBase64 = body.data.foto_base64
      ? String(body.data.foto_base64).replace(/\s+/g, "")
      : null;

    const fotoMime = body.data.foto_mime ? String(body.data.foto_mime).toLowerCase() : null;

    await db.query(
      `UPDATE jugadores
          SET foto_base64 = ?, foto_mime = ?
        WHERE rut_jugador = ?`,
      [fotoBase64, fotoMime, rutJugador]
    );

    return reply.send({ ok: true });
  });

  /* ──────────────────────────────────────────────────────────────
     GET /api/portal-apoderado/jugadores/:rut/resumen
  ────────────────────────────────────────────────────────────── */
  app.get("/jugadores/:rut/resumen", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);
    if (!auth) return;

    if (!(await assertGuardOrReply(auth.rut, reply))) return;

    const parsed = RutJugadorParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "BAD_REQUEST" });

    const rutJugador = parsed.data.rut;
    const db = getDb();

    const okOwn = await assertJugadorPertenece(db, rutJugador, auth.rut);
    if (!okOwn) return reply.code(403).send({ ok: false, message: "FORBIDDEN" });

    const [jugRows] = await db.query<any[]>(
      `SELECT
          j.id,
          j.rut_jugador,
          j.nombre_jugador,
          j.fecha_nacimiento,
          j.edad,
          j.telefono,
          j.email,
          j.direccion,
          j.comuna_id,
          j.posicion_id,
          j.categoria_id,
          j.talla_polera,
          j.talla_short,
          j.establec_educ_id,
          j.prevision_medica_id,
          j.nombre_apoderado,
          j.rut_apoderado,
          j.telefono_apoderado,
          j.peso,
          j.estatura,
          j.observaciones,
          j.estado_id,
          j.estadistica_id,
          j.sucursal_id,
          (j.contrato_prestacion IS NOT NULL AND j.contrato_prestacion <> '') AS tiene_contrato,
          c.nombre  AS categoria_nombre,
          pz.nombre AS posicion_nombre,
          es.nombre AS estado_nombre,
          sr.nombre AS sucursal_nombre,
          co.nombre AS comuna_nombre,
          ee.nombre AS establec_educ_nombre,
          pm.nombre AS prevision_medica_nombre
       FROM jugadores j
       LEFT JOIN categorias       c  ON c.id  = j.categoria_id
       LEFT JOIN posiciones       pz ON pz.id = j.posicion_id
       LEFT JOIN estado           es ON es.id = j.estado_id
       LEFT JOIN sucursales_real  sr ON sr.id = j.sucursal_id
       LEFT JOIN comunas          co ON co.id = j.comuna_id
       LEFT JOIN establec_educ    ee ON ee.id = j.establec_educ_id
       LEFT JOIN prevision_medica pm ON pm.id = j.prevision_medica_id
       WHERE j.rut_jugador = ?
       LIMIT 1`,
      [rutJugador]
    );

    const r = jugRows?.[0] ?? null;
    if (!r) return reply.code(404).send({ ok: false, message: "NOT_FOUND" });

    const jugador = {
      id: r.id,
      rut_jugador: r.rut_jugador,
      nombre_jugador: r.nombre_jugador,
      fecha_nacimiento: r.fecha_nacimiento,
      edad: r.edad,
      telefono: r.telefono,
      email: r.email,
      direccion: r.direccion,
      comuna_id: r.comuna_id,
      posicion_id: r.posicion_id,
      categoria_id: r.categoria_id,
      talla_polera: r.talla_polera,
      talla_short: r.talla_short,
      establec_educ_id: r.establec_educ_id,
      prevision_medica_id: r.prevision_medica_id,
      nombre_apoderado: r.nombre_apoderado,
      rut_apoderado: r.rut_apoderado,
      telefono_apoderado: r.telefono_apoderado,
      peso: r.peso,
      estatura: r.estatura,
      observaciones: r.observaciones,
      estado_id: r.estado_id,
      estadistica_id: r.estadistica_id,
      sucursal_id: r.sucursal_id,
      tiene_contrato: Boolean(r.tiene_contrato),

      categoria: r.categoria_nombre ? { id: safeNum(r.categoria_id), nombre: r.categoria_nombre } : null,
      posicion: r.posicion_nombre ? { id: safeNum(r.posicion_id), nombre: r.posicion_nombre } : null,
      estado: r.estado_nombre ? { id: safeNum(r.estado_id), nombre: r.estado_nombre } : null,
      sucursal: r.sucursal_nombre ? { id: safeNum(r.sucursal_id), nombre: r.sucursal_nombre } : null,
      comuna: r.comuna_nombre ? { id: safeNum(r.comuna_id), nombre: r.comuna_nombre } : null,
      establec_educ: r.establec_educ_nombre
        ? { id: safeNum(r.establec_educ_id), nombre: r.establec_educ_nombre }
        : null,
      prevision_medica: r.prevision_medica_nombre
        ? { id: safeNum(r.prevision_medica_id), nombre: r.prevision_medica_nombre }
        : null,
    };

    const [payRows] = await db.query<any[]>(
      `SELECT
          p.*,
          tp.id AS tp_id, tp.nombre AS tp_nombre,
          mp.id AS mp_id, mp.nombre AS mp_nombre,
          sp.id AS sp_id, sp.nombre AS sp_nombre
       FROM pagos_jugador p
       LEFT JOIN tipo_pago tp      ON tp.id = p.tipo_pago_id
       LEFT JOIN medio_pago mp     ON mp.id = p.medio_pago_id
       LEFT JOIN situacion_pago sp ON sp.id = p.situacion_pago_id
       WHERE p.jugador_rut = ?
       ORDER BY p.fecha_pago DESC, p.id DESC`,
      [rutJugador]
    );

    const pagos = (payRows || []).map((x) => ({
      id: x.id,
      jugador_rut: x.jugador_rut,
      tipo_pago_id: x.tipo_pago_id,
      situacion_pago_id: x.situacion_pago_id,
      medio_pago_id: x.medio_pago_id,
      monto: Number(x.monto || 0),
      fecha_pago: x.fecha_pago,
      comprobante_url: x.comprobante_url ?? null,
      observaciones: x.observaciones ?? null,
      tipo_pago: { id: x.tp_id ?? x.tipo_pago_id, nombre: x.tp_nombre ?? null },
      medio_pago: { id: x.mp_id ?? x.medio_pago_id, nombre: x.mp_nombre ?? null },
      situacion_pago: { id: x.sp_id ?? x.situacion_pago_id, nombre: x.sp_nombre ?? null },
    }));

    let estadisticas: any = null;
    if (r.estadistica_id) {
      try {
        const [st] = await db.query<any[]>(
          `SELECT *
             FROM estadisticas
            WHERE estadistica_id = ?
            ORDER BY id DESC
            LIMIT 1`,
          [r.estadistica_id]
        );
        estadisticas = st?.[0] ?? null;
      } catch {
        estadisticas = null;
      }
    }

    return reply.send({ ok: true, jugador, estadisticas, pagos });
  });

  /* ──────────────────────────────────────────────────────────────
     GET /api/portal-apoderado/jugadores/:rut/contrato
  ────────────────────────────────────────────────────────────── */
  app.get("/jugadores/:rut/contrato", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);
    if (!auth) return;

    if (!(await assertGuardOrReply(auth.rut, reply))) return;

    const parsed = RutJugadorParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "BAD_REQUEST" });

    const rutJugador = parsed.data.rut;
    const db = getDb();

    const okOwn = await assertJugadorPertenece(db, rutJugador, auth.rut);
    if (!okOwn) return reply.code(403).send({ ok: false, message: "FORBIDDEN" });

    const [rows] = await db.query<any[]>(
      `SELECT contrato_prestacion, contrato_prestacion_mime
         FROM jugadores
        WHERE rut_jugador = ?
        LIMIT 1`,
      [rutJugador]
    );

    const r = rows?.[0];
    if (!r) return reply.code(404).send({ ok: false, message: "NOT_FOUND" });

    if (!hasB64(r.contrato_prestacion)) {
      return reply.code(404).send({ ok: false, message: "NO_CONTRATO" });
    }

    const mime = String(r.contrato_prestacion_mime || "application/pdf").toLowerCase();
    if (!mime.includes("application/pdf")) {
      return reply.code(415).send({ ok: false, message: "UNSUPPORTED_MEDIA_TYPE" });
    }

    const cleaned = cleanBase64(r.contrato_prestacion);

    let buf: Buffer;
    try {
      buf = Buffer.from(cleaned, "base64");
    } catch {
      return reply.code(500).send({ ok: false, message: "CONTRATO_INVALIDO" });
    }

    reply.header("Content-Type", "application/pdf");
    reply.header("Content-Disposition", `inline; filename="Contrato_${rutJugador}.pdf"`);
    reply.header("Cache-Control", "no-store, max-age=0");

    return reply.send(buf);
  });

  /* ──────────────────────────────────────────────────────────────
     GET /api/portal-apoderado/jugadores/:rut/pagos
  ────────────────────────────────────────────────────────────── */
  app.get("/jugadores/:rut/pagos", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);
    if (!auth) return;

    if (!(await assertGuardOrReply(auth.rut, reply))) return;

    const parsed = RutJugadorParam.safeParse(req.params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "BAD_REQUEST" });

    const rutJugador = parsed.data.rut;
    const db = getDb();

    const okOwn = await assertJugadorPertenece(db, rutJugador, auth.rut);
    if (!okOwn) return reply.code(403).send({ ok: false, message: "FORBIDDEN" });

    const [payRows] = await db.query<any[]>(
      `SELECT
          p.*,
          tp.id AS tp_id, tp.nombre AS tp_nombre,
          mp.id AS mp_id, mp.nombre AS mp_nombre,
          sp.id AS sp_id, sp.nombre AS sp_nombre
       FROM pagos_jugador p
       LEFT JOIN tipo_pago tp      ON tp.id = p.tipo_pago_id
       LEFT JOIN medio_pago mp     ON mp.id = p.medio_pago_id
       LEFT JOIN situacion_pago sp ON sp.id = p.situacion_pago_id
       WHERE p.jugador_rut = ?
       ORDER BY p.fecha_pago DESC, p.id DESC`,
      [rutJugador]
    );

    const pagos = (payRows || []).map((x) => ({
      id: x.id,
      jugador_rut: x.jugador_rut,
      tipo_pago_id: x.tipo_pago_id,
      situacion_pago_id: x.situacion_pago_id,
      medio_pago_id: x.medio_pago_id,
      monto: Number(x.monto || 0),
      fecha_pago: x.fecha_pago,
      comprobante_url: x.comprobante_url ?? null,
      observaciones: x.observaciones ?? null,
      tipo_pago: { id: x.tp_id ?? x.tipo_pago_id, nombre: x.tp_nombre ?? null },
      medio_pago: { id: x.mp_id ?? x.medio_pago_id, nombre: x.mp_nombre ?? null },
      situacion_pago: { id: x.sp_id ?? x.situacion_pago_id, nombre: x.sp_nombre ?? null },
    }));

    return reply.send({ ok: true, pagos });
  });
}
