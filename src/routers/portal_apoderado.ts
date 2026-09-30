// src/routers/portal_apoderado.ts

import type { FastifyInstance, FastifyPluginOptions, FastifyReply, FastifyRequest } from "fastify";

import { z } from "zod";

import { getDb } from "../db";

import { decryptNullable, decryptRut, rutBlindIndex, validateCryptoConfiguration } from "../services/crypto";

import { requireAuth, requireApoderado } from "../middlewares/authz";

/* =========================================================

   TIPOS AUTH

========================================================= */

type ApoderadoAuth = {
  type: "apoderado";

  rut: string;

  apoderado_id?: number;
};

function getApoderadoAuth(req: FastifyRequest, reply: FastifyReply): ApoderadoAuth | null {
  const auth = (req as any).auth;

  const user = (req as any).user;

  const source = auth ?? user ?? null;

  const type = String(source?.type ?? "").toLowerCase();

  const rut = String(source?.rut ?? "");

  if (type !== "apoderado" || !/^\d{7,8}$/.test(rut)) {
    reply.code(401).send({
      ok: false,

      message: "UNAUTHORIZED",
    });

    return null;
  }

  const rawApoderadoId = Number(source?.apoderado_id);

  const apoderado_id = Number.isInteger(rawApoderadoId) && rawApoderadoId > 0 ? rawApoderadoId : undefined;

  return {
    type: "apoderado",

    rut,

    apoderado_id,
  };
}

/* =========================================================

   GUARD PORTAL

========================================================= */

async function requireApoderadoPortalOk(db: any, rut: string) {
  const [rows] = await db.query(
    `
      SELECT must_change_password
      FROM apoderados_auth
      WHERE rut_apoderado_idx = ?
      LIMIT 1
    `,
    [rutBlindIndex(rut)]
  );

  const arr = rows as any[];

  if (!arr?.length) {
    return {
      ok: false as const,
      code: 401,
      message: "UNAUTHORIZED",
    };
  }

  if (Number(arr[0]?.must_change_password) === 1) {
    return {
      ok: false as const,
      code: 403,
      message: "PASSWORD_CHANGE_REQUIRED",
    };
  }

  return {
    ok: true as const,
  };
}

async function assertGuardOrReply(db: any, rut: string, reply: FastifyReply): Promise<boolean> {
  const guard = await requireApoderadoPortalOk(db, rut);

  if (!guard.ok) {
    reply.code(guard.code).send({
      ok: false,

      message: guard.message,
    });

    return false;
  }

  return true;
}

/* =========================================================

   SCHEMAS

========================================================= */

const RutJugadorParam = z

  .object({
    rut: z.string().regex(/^\d{7,8}$/),
  })

  .strict();

const JugadorIdParam = z

  .object({
    id: z.coerce.number().int().positive(),
  })

  .strict();

const FotoBodySchema = z

  .object({
    foto_base64: z.string().trim().nullable(),

    foto_mime: z.string().trim().nullable(),
  })

  .strict();

/* =========================================================

   HELPERS GENERALES

========================================================= */

const safeNum = (value: any) => {
  const number = Number(value);

  return Number.isFinite(number) ? number : null;
};

const hasB64 = (value: any) => {
  const string = String(value ?? "").trim();

  return string.length > 50;
};

const cleanBase64 = (raw: any) => {
  const string = String(raw ?? "").trim();

  return string

    .replace(/^data:application\/pdf;base64,/, "")

    .replace(/^data:.*;base64,/, "")

    .replace(/\s+/g, "");
};

const isValidFotoMime = (mime: any) => {
  const normalized = String(mime ?? "")
    .toLowerCase()

    .trim();

  return ["image/jpeg", "image/jpg", "image/png", "image/webp"].includes(normalized);
};

function decryptText(value: unknown): string | null {
  if (value === null || value === undefined || String(value).trim() === "") {
    return null;
  }
  return decryptNullable(String(value));
}

function decryptRutNumber(value: unknown): number | null {
  if (value === null || value === undefined || String(value).trim() === "") {
    return null;
  }
  const decrypted = decryptRut(String(value));
  const numeric = Number(decrypted);
  return Number.isFinite(numeric) ? numeric : null;
}

function decryptRutString(value: unknown): string | null {
  if (value === null || value === undefined || String(value).trim() === "") {
    return null;
  }
  return decryptRut(String(value));
}

function decryptAcademiaName(value: unknown): string | null {
  return decryptText(value);
}

/* =========================================================

   JUGADOR - AUTORIZACIÓN POR ID

   La autorización NO depende de academia enviada por cliente.

   El jugador solamente es visible cuando:

   jugador.id = solicitado

   +

   jugador.rut_apoderado = apoderado autenticado

========================================================= */

async function getJugadorBaseById(db: any, jugadorId: number, rutApoderado: string) {
  const [rows] = await db.query(
    `
      SELECT
        j.id,
        j.academia_id,
        j.deporte_id,

        j.rut_jugador_enc,
        j.nombre_jugador_enc,
        j.fecha_nacimiento_enc,
        j.edad,
        j.telefono_enc,
        j.email_enc,
        j.direccion_enc,

        j.comuna_id,
        j.posicion_id,
        j.categoria_id,

        j.talla_polera,
        j.talla_short,

        j.establec_educ_id,
        j.prevision_medica_id,

        j.nombre_apoderado_enc,
        j.rut_apoderado_enc,
        j.telefono_apoderado_enc,

        j.peso,
        j.estatura,
        j.observaciones_enc,

        j.estado_id,
        j.estadistica_id,
        j.sucursal_id,

        (
          j.contrato_prestacion IS NOT NULL
          AND j.contrato_prestacion <> ''
        ) AS tiene_contrato,

        a.nombre_enc AS academia_nombre_enc,
        d.nombre AS deporte_nombre,

        c.nombre AS categoria_nombre,
        pz.nombre AS posicion_nombre,
        es.nombre AS estado_nombre,

        sr.nombre AS sucursal_nombre,

        co.nombre AS comuna_nombre,
        ee.nombre AS establec_educ_nombre,
        pm.nombre AS prevision_medica_nombre

      FROM jugadores j

      LEFT JOIN academias a
        ON a.id = j.academia_id

      LEFT JOIN deportes d
        ON d.id = j.deporte_id

      LEFT JOIN categorias c
        ON c.id = j.categoria_id

      LEFT JOIN posiciones pz
        ON pz.id = j.posicion_id

      LEFT JOIN estado es
        ON es.id = j.estado_id

      LEFT JOIN sucursales_real sr
        ON sr.id = j.sucursal_id
        AND sr.academia_id = j.academia_id

      LEFT JOIN comunas co
        ON co.id = j.comuna_id

      LEFT JOIN establec_educ ee
        ON ee.id = j.establec_educ_id

      LEFT JOIN prevision_medica pm
        ON pm.id = j.prevision_medica_id

      WHERE j.id = ?
        AND j.rut_apoderado_idx = ?

      LIMIT 1
    `,
    [jugadorId, rutBlindIndex(rutApoderado)]
  );

  return (rows as any[])?.[0] ?? null;
}

/* =========================================================

   RESOLVER JUGADOR LEGACY POR RUT

   Se conserva para no romper el frontend antiguo.

   Si el mismo RUT está registrado más de una vez para el

   mismo apoderado, el endpoint legacy deja de ser inequívoco.

========================================================= */

async function resolveJugadorLegacyByRut(db: any, rutJugador: string, rutApoderado: string) {
  const [rows] = await db.query(
    `
      SELECT
        id,
        academia_id,
        deporte_id,
        rut_jugador_enc,
        nombre_jugador_enc
      FROM jugadores
      WHERE rut_jugador_idx = ?
        AND rut_apoderado_idx = ?
      ORDER BY id ASC
    `,
    [rutBlindIndex(rutJugador), rutBlindIndex(rutApoderado)]
  );

  const arr = rows as any[];

  if (!arr?.length) {
    return {
      ok: false as const,
      code: 403,
      message: "FORBIDDEN",
      jugador: null,
    };
  }

  if (arr.length > 1) {
    return {
      ok: false as const,
      code: 409,
      message: "AMBIGUOUS_PLAYER_RUT_USE_ID",
      jugador: null,
    };
  }

  return {
    ok: true as const,
    jugador: arr[0],
  };
}

/* =========================================================

   SUCURSALES N:M

========================================================= */

async function getSucursalesJugador(
  db: any,

  jugadorId: number,

  academiaId: number | null,

  legacySucursal?: {
    id: any;

    nombre: any;
  } | null
) {
  try {
    const [rows] = await db.query(
      `

        SELECT

          sr.id,

          sr.nombre

        FROM jugador_sucursal js

        INNER JOIN sucursales_real sr

          ON sr.id = js.sucursal_id

        WHERE js.jugador_id = ?

          AND sr.academia_id = ?

        ORDER BY sr.nombre ASC, sr.id ASC

      `,

      [jugadorId, academiaId]
    );

    if (Array.isArray(rows) && rows.length > 0) {
      return rows.map((row: any) => ({
        id: safeNum(row.id),

        nombre: String(row.nombre ?? ""),
      }));
    }
  } catch {
    /*

     * Compatibilidad temporal:

     * si una instalación antigua todavía no posee

     * jugador_sucursal, utilizamos sucursal_id legacy.

     */
  }

  if (legacySucursal?.id != null && safeNum(legacySucursal.id) && String(legacySucursal?.nombre ?? "").trim()) {
    return [
      {
        id: safeNum(legacySucursal.id),

        nombre: String(legacySucursal.nombre),
      },
    ];
  }

  return [];
}

/* =========================================================

   NORMALIZAR JUGADOR

========================================================= */

async function normalizeJugadorDetalle(db: any, row: any) {
  const academiaId = safeNum(row?.academia_id);

  const sucursales = await getSucursalesJugador(
    db,
    Number(row.id),
    academiaId,
    row?.sucursal_nombre
      ? {
          id: row?.sucursal_id,
          nombre: row?.sucursal_nombre,
        }
      : null
  );

  return {
    id: safeNum(row.id),
    academia_id: academiaId,
    deporte_id: safeNum(row.deporte_id),

    rut_jugador: decryptRutNumber(row.rut_jugador_enc),
    nombre_jugador: decryptText(row.nombre_jugador_enc),
    fecha_nacimiento: decryptText(row.fecha_nacimiento_enc),
    edad: row.edad,
    telefono: decryptText(row.telefono_enc),
    email: decryptText(row.email_enc),
    direccion: decryptText(row.direccion_enc),

    comuna_id: row.comuna_id,
    posicion_id: row.posicion_id,
    categoria_id: row.categoria_id,

    talla_polera: row.talla_polera,
    talla_short: row.talla_short,

    establec_educ_id: row.establec_educ_id,
    prevision_medica_id: row.prevision_medica_id,

    nombre_apoderado: decryptText(row.nombre_apoderado_enc),
    rut_apoderado: decryptRutNumber(row.rut_apoderado_enc),
    telefono_apoderado: decryptText(row.telefono_apoderado_enc),

    peso: row.peso,
    estatura: row.estatura,
    observaciones: decryptText(row.observaciones_enc),

    estado_id: row.estado_id,
    estadistica_id: row.estadistica_id,

    /*
     * Se conserva temporalmente por compatibilidad.
     */
    sucursal_id: row.sucursal_id,

    tiene_contrato: Boolean(row.tiene_contrato),

    academia: academiaId
      ? {
          id: academiaId,
          nombre: decryptAcademiaName(row.academia_nombre_enc),
        }
      : null,

    deporte: safeNum(row.deporte_id)
      ? {
          id: safeNum(row.deporte_id),
          nombre: row.deporte_nombre ?? null,
        }
      : null,

    categoria: row.categoria_nombre
      ? {
          id: safeNum(row.categoria_id),
          nombre: row.categoria_nombre,
        }
      : null,

    posicion: row.posicion_nombre
      ? {
          id: safeNum(row.posicion_id),
          nombre: row.posicion_nombre,
        }
      : null,

    estado: row.estado_nombre
      ? {
          id: safeNum(row.estado_id),
          nombre: row.estado_nombre,
        }
      : null,

    /*
     * Compatibilidad con frontend anterior.
     */
    sucursal: sucursales[0] ?? null,

    /*
     * Nueva relación oficial N:M.
     */
    sucursales,

    comuna: row.comuna_nombre
      ? {
          id: safeNum(row.comuna_id),
          nombre: row.comuna_nombre,
        }
      : null,

    establec_educ: row.establec_educ_nombre
      ? {
          id: safeNum(row.establec_educ_id),
          nombre: row.establec_educ_nombre,
        }
      : null,

    prevision_medica: row.prevision_medica_nombre
      ? {
          id: safeNum(row.prevision_medica_id),
          nombre: row.prevision_medica_nombre,
        }
      : null,
  };
}

/* =========================================================

   PAGOS DEL JUGADOR

   La nueva identidad utiliza:

   jugador_id + academia_id.

========================================================= */

async function getPagosJugador(db: any, jugador: any) {
  const jugadorId = Number(jugador?.id);

  const academiaId = Number(jugador?.academia_id);

  if (!Number.isInteger(jugadorId) || jugadorId <= 0 || !Number.isInteger(academiaId) || academiaId <= 0) {
    return [];
  }

  /* =======================================================

     1. CABECERAS DE PAGOS

  ======================================================= */

  const [rows]: any = await db.query(
    `

      SELECT

        p.id,

        p.academia_id,

        p.jugador_id,

        p.sucursal_id,

        p.plan_catalogo_id,

        p.situacion_pago_id,

        p.monto_base,

        p.monto_descuento,

        p.monto_total,

        p.fecha_pago,

        p.medio_pago_id,

        p.comprobante_url,

        p.observaciones,

        p.created_at,

        mp.id AS mp_id,

        mp.nombre AS mp_nombre,

        sp.id AS sp_id,

        sp.nombre AS sp_nombre,

        pc.id AS plan_id,

        pc.nombre AS plan_nombre,

        sr.id AS pago_sucursal_id,

        sr.nombre AS pago_sucursal_nombre

      FROM pagos_jugador p

      LEFT JOIN medio_pago mp

        ON mp.id = p.medio_pago_id

      LEFT JOIN situacion_pago sp

        ON sp.id = p.situacion_pago_id

      LEFT JOIN planes_catalogo pc

        ON pc.id = p.plan_catalogo_id

      LEFT JOIN sucursales_real sr

        ON sr.id = p.sucursal_id

        AND sr.academia_id = p.academia_id

      WHERE p.academia_id = ?

        AND p.jugador_id = ?

      ORDER BY

        p.fecha_pago DESC,

        p.id DESC

    `,

    [academiaId, jugadorId]
  );

  const paymentRows = Array.isArray(rows) ? rows : [];

  if (paymentRows.length === 0) {
    return [];
  }

  /* =======================================================

     2. DETALLES DE TODOS LOS PAGOS

     Una sola consulta para evitar N+1.

  ======================================================= */

  const pagoIds = paymentRows.map((row: any) => Number(row?.id)).filter((id: number) => Number.isInteger(id) && id > 0);

  const detallesPorPago = new Map<number, any[]>();

  if (pagoIds.length > 0) {
    const placeholders = pagoIds.map(() => "?").join(", ");

    const [detailRows]: any = await db.query(
      `

        SELECT

          pd.id,

          pd.pago_id,

          pd.tipo_pago_id,

          pd.tarifa_id,

          pd.plan_regla_id,

          pd.monto_base,

          pd.monto_descuento,

          pd.monto_total,

          pd.origen,

          pd.observaciones,

          pd.created_at,

          pd.updated_at,

          tp.nombre AS tipo_pago_nombre

        FROM pago_detalle pd

        INNER JOIN tipo_pago tp

          ON tp.id = pd.tipo_pago_id

        WHERE pd.pago_id IN (${placeholders})

        ORDER BY

          pd.pago_id ASC,

          pd.id ASC

      `,

      pagoIds
    );

    for (const detail of Array.isArray(detailRows) ? detailRows : []) {
      const pagoId = Number(detail?.pago_id);

      if (!Number.isInteger(pagoId) || pagoId <= 0) {
        continue;
      }

      if (!detallesPorPago.has(pagoId)) {
        detallesPorPago.set(pagoId, []);
      }

      detallesPorPago.get(pagoId)?.push({
        id: safeNum(detail.id),

        pago_id: safeNum(detail.pago_id),

        tipo_pago_id: safeNum(detail.tipo_pago_id),

        tipo_pago_nombre: detail.tipo_pago_nombre ?? null,

        /*

         * También dejamos objeto normalizado.

         * Esto facilita el consumo desde React.

         */

        tipo_pago: detail.tipo_pago_id
          ? {
              id: safeNum(detail.tipo_pago_id),

              nombre: detail.tipo_pago_nombre ?? null,
            }
          : null,

        tarifa_id: safeNum(detail.tarifa_id),

        plan_regla_id: safeNum(detail.plan_regla_id),

        monto_base: detail.monto_base == null ? null : Number(detail.monto_base),

        monto_descuento: detail.monto_descuento == null ? null : Number(detail.monto_descuento),

        monto_total: detail.monto_total == null ? null : Number(detail.monto_total),

        origen: detail.origen ?? null,

        observaciones: detail.observaciones ?? null,

        created_at: detail.created_at ?? null,

        updated_at: detail.updated_at ?? null,
      });
    }
  }

  /* =======================================================

     3. RESPUESTA NORMALIZADA

  ======================================================= */

  return paymentRows.map((row: any) => {
    const pagoId = Number(row?.id);

    const detalles = detallesPorPago.get(pagoId) ?? [];

    return {
      id: safeNum(row.id),

      academia_id: safeNum(row.academia_id),

      jugador_id: safeNum(row.jugador_id),

      sucursal_id: safeNum(row.sucursal_id),

      plan_catalogo_id: safeNum(row.plan_catalogo_id),

      situacion_pago_id: safeNum(row.situacion_pago_id),

      medio_pago_id: safeNum(row.medio_pago_id),

      /*

       * Compatibilidad con frontend anterior.

       */

      monto: row.monto_total != null ? Number(row.monto_total) : 0,

      monto_base: row.monto_base == null ? null : Number(row.monto_base),

      monto_descuento: row.monto_descuento == null ? null : Number(row.monto_descuento),

      monto_total: row.monto_total == null ? null : Number(row.monto_total),

      fecha_pago: row.fecha_pago ?? null,

      comprobante_url: row.comprobante_url ?? null,

      observaciones: row.observaciones ?? null,

      created_at: row.created_at ?? null,

      medio_pago: row.mp_id
        ? {
            id: safeNum(row.mp_id),

            nombre: row.mp_nombre ?? null,
          }
        : null,

      situacion_pago: row.sp_id
        ? {
            id: safeNum(row.sp_id),

            nombre: row.sp_nombre ?? null,
          }
        : null,

      plan: row.plan_id
        ? {
            id: safeNum(row.plan_id),

            nombre: row.plan_nombre ?? null,
          }
        : null,

      sucursal: row.pago_sucursal_id
        ? {
            id: safeNum(row.pago_sucursal_id),

            nombre: row.pago_sucursal_nombre ?? null,
          }
        : null,

      /*

       * Nueva estructura oficial para portal.

       */

      detalles,
    };
  });
}

/* =========================================================

   ESTADÍSTICAS MULTIDEPORTE

   Lectura segura para portal de apoderados.

   El portal NO crea stats_base ni filas deportivas.

   Solo consulta estadísticas existentes.

   El navegador NO decide academia_id ni deporte_id.

========================================================= */

const PORTAL_SPORT_TABLE: Record<number, string> = {
  1: "stats_futbol",

  2: "stats_voley",

  3: "stats_tenis",

  4: "stats_padel",

  5: "stats_tenis_mesa",

  6: "stats_basquet",

  7: "stats_american_football",
};

type PortalStatsResult = {
  supported: boolean;

  table: string | null;

  stats_id: number | null;

  base: Record<string, any> | null;

  sport: Record<string, any> | null;

  flat: Record<string, any>;

  tiene_estadisticas: boolean;
};

async function getEstadisticasJugador(db: any, jugador: any): Promise<PortalStatsResult> {
  const jugadorId = Number(jugador?.id);

  const academiaId = Number(jugador?.academia_id);

  const deporteId = Number(jugador?.deporte_id);

  if (
    !Number.isInteger(jugadorId) ||
    jugadorId <= 0 ||
    !Number.isInteger(academiaId) ||
    academiaId <= 0 ||
    !Number.isInteger(deporteId) ||
    deporteId <= 0
  ) {
    return {
      supported: false,

      table: null,

      stats_id: null,

      base: null,

      sport: null,

      flat: {},

      tiene_estadisticas: false,
    };
  }

  const table = PORTAL_SPORT_TABLE[deporteId] ?? null;

  if (!table) {
    return {
      supported: false,

      table: null,

      stats_id: null,

      base: null,

      sport: null,

      flat: {},

      tiene_estadisticas: false,
    };
  }

  const [baseRows] = await db.query(
    `

      SELECT *

      FROM stats_base

      WHERE academia_id = ?

        AND deporte_id = ?

        AND jugador_id = ?

        AND partido_id IS NULL

      ORDER BY id DESC

      LIMIT 1

    `,

    [academiaId, deporteId, jugadorId]
  );

  const base = baseRows?.[0] ?? null;

  /*

   * Un jugador puede existir perfectamente

   * sin estadísticas todavía.

   */

  if (!base) {
    return {
      supported: true,

      table,

      stats_id: null,

      base: null,

      sport: null,

      flat: {},

      tiene_estadisticas: false,
    };
  }

  const statsId = Number(base.id);

  const [sportRows] = await db.query(
    `
    SELECT *
    FROM \`${table}\`
    WHERE stats_id = ?
    LIMIT 1
  `,
    [statsId]
  );

  const sport = sportRows?.[0] ?? null;

  /*

   * Compatibilidad con portal antiguo:

   * mantenemos también una representación plana.

   */

  const flat = {
    ...(base || {}),

    ...(sport || {}),
  };

  return {
    supported: true,

    table,

    stats_id: Number.isInteger(statsId) && statsId > 0 ? statsId : null,

    base,

    sport,

    flat,

    tiene_estadisticas: Boolean(base),
  };
}

/* =========================================================

   ROUTER

========================================================= */

export default async function portal_apoderado(app: FastifyInstance, _opts: FastifyPluginOptions) {
  validateCryptoConfiguration();

  /*

   * Blindaje completo del módulo.

   */

  app.addHook("preHandler", requireAuth);

  app.addHook("preHandler", requireApoderado);

  /* =======================================================

     GET /me

  ======================================================= */

  app.get("/me", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);

    if (!auth) {
      return;
    }

    const db = getDb();

    if (!(await assertGuardOrReply(db, auth.rut, reply))) {
      return;
    }

    const rutIdx = rutBlindIndex(auth.rut);

    let apoderado: any = null;

    const [authRows]: any[] = await db.query(
      `
        SELECT
          apoderado_id,
          rut_apoderado_enc,
          nombre_apoderado_enc
        FROM apoderados_auth
        WHERE rut_apoderado_idx = ?
        LIMIT 1
      `,
      [rutIdx]
    );

    if (authRows?.length) {
      apoderado = {
        apoderado_id: authRows[0]?.apoderado_id ?? null,
        rut_apoderado: decryptRutString(authRows[0]?.rut_apoderado_enc) ?? auth.rut,
        nombre_apoderado: decryptText(authRows[0]?.nombre_apoderado_enc) ?? "",
        email: null,
        telefono: null,
      };
    }

    /*
     * apoderados_auth no contiene email ni teléfono en el esquema actual.
     * Para mantener el contrato del portal, se obtienen desde el jugador
     * relacionado más reciente.
     */
    const [fallbackRows]: any[] = await db.query(
      `
        SELECT
          nombre_apoderado_enc,
          telefono_apoderado_enc,
          email_enc
        FROM jugadores
        WHERE rut_apoderado_idx = ?
        ORDER BY id DESC
        LIMIT 1
      `,
      [rutIdx]
    );

    if (fallbackRows?.length) {
      const fallback = fallbackRows[0];

      apoderado = {
        ...(apoderado || {}),
        rut_apoderado: apoderado?.rut_apoderado ?? auth.rut,
        nombre_apoderado:
          String(apoderado?.nombre_apoderado ?? "").trim() ||
          String(decryptText(fallback?.nombre_apoderado_enc) ?? "").trim(),
        email: apoderado?.email ?? decryptText(fallback?.email_enc),
        telefono: apoderado?.telefono ?? decryptText(fallback?.telefono_apoderado_enc),
      };
    }

    const [summaryRows]: any[] = await db.query(
      `
        SELECT
          COUNT(*) AS jugadores,
          COUNT(DISTINCT academia_id) AS academias,
          COUNT(DISTINCT deporte_id) AS deportes
        FROM jugadores
        WHERE rut_apoderado_idx = ?
      `,
      [rutIdx]
    );

    const summary = summaryRows?.[0] ?? {};

    return reply.send({
      ok: true,
      apoderado: {
        id: safeNum(apoderado?.apoderado_id) ?? auth.apoderado_id ?? null,
        rut_apoderado: String(apoderado?.rut_apoderado ?? auth.rut),
        nombre_apoderado: String(apoderado?.nombre_apoderado ?? "").trim(),
        email: apoderado?.email ?? null,
        telefono: apoderado?.telefono ?? null,
      },
      resumen: {
        jugadores: Number(summary?.jugadores ?? 0),
        academias: Number(summary?.academias ?? 0),
        deportes: Number(summary?.deportes ?? 0),
      },
    });
  });

  /* =======================================================

     GET /mis-jugadores

     FUENTE PRINCIPAL DEL NUEVO PORTAL.

     Devuelve TODAS las inscripciones relacionadas con el

     RUT del apoderado autenticado, sin limitar por academia.

  ======================================================= */

  app.get("/mis-jugadores", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);

    if (!auth) {
      return;
    }

    const db = getDb();

    if (!(await assertGuardOrReply(db, auth.rut, reply))) {
      return;
    }

    const rutIdx = rutBlindIndex(auth.rut);

    const [rows]: any[] = await db.query(
      `
        SELECT
          j.id,
          j.academia_id,
          j.deporte_id,

          j.rut_jugador_enc,
          j.nombre_jugador_enc,

          j.fecha_nacimiento_enc,
          j.edad,

          j.estado_id,
          j.categoria_id,
          j.posicion_id,

          j.sucursal_id,

          (
            j.contrato_prestacion IS NOT NULL
            AND j.contrato_prestacion <> ''
          ) AS tiene_contrato,

          a.nombre_enc AS academia_nombre_enc,
          d.nombre AS deporte_nombre,

          e.nombre AS estado_nombre,
          c.nombre AS categoria_nombre,
          p.nombre AS posicion_nombre,

          sr.nombre AS sucursal_nombre

        FROM jugadores j

        LEFT JOIN academias a
          ON a.id = j.academia_id

        LEFT JOIN deportes d
          ON d.id = j.deporte_id

        LEFT JOIN estado e
          ON e.id = j.estado_id

        LEFT JOIN categorias c
          ON c.id = j.categoria_id

        LEFT JOIN posiciones p
          ON p.id = j.posicion_id

        LEFT JOIN sucursales_real sr
          ON sr.id = j.sucursal_id
          AND sr.academia_id = j.academia_id

        WHERE j.rut_apoderado_idx = ?

        ORDER BY j.id ASC
      `,
      [rutIdx]
    );

    const jugadores: any[] = [];

    for (const row of rows ?? []) {
      const sucursales = await getSucursalesJugador(
        db,
        Number(row.id),
        safeNum(row.academia_id),
        row.sucursal_nombre
          ? {
              id: row.sucursal_id,
              nombre: row.sucursal_nombre,
            }
          : null
      );

      jugadores.push({
        id: safeNum(row.id),
        academia_id: safeNum(row.academia_id),
        deporte_id: safeNum(row.deporte_id),

        rut_jugador: decryptRutNumber(row.rut_jugador_enc),
        nombre_jugador: decryptText(row.nombre_jugador_enc),
        fecha_nacimiento: decryptText(row.fecha_nacimiento_enc),
        edad: row.edad,

        estado_id: row.estado_id,
        categoria_id: row.categoria_id,
        posicion_id: row.posicion_id,

        /*
         * Compatibilidad temporal.
         */
        sucursal_id: row.sucursal_id,

        tiene_contrato: Boolean(row.tiene_contrato),

        academia: safeNum(row.academia_id)
          ? {
              id: safeNum(row.academia_id),
              nombre: decryptAcademiaName(row.academia_nombre_enc),
            }
          : null,

        deporte: safeNum(row.deporte_id)
          ? {
              id: safeNum(row.deporte_id),
              nombre: row.deporte_nombre ?? null,
            }
          : null,

        estado: row.estado_nombre
          ? {
              id: safeNum(row.estado_id),
              nombre: row.estado_nombre,
            }
          : null,

        categoria: row.categoria_nombre
          ? {
              id: safeNum(row.categoria_id),
              nombre: row.categoria_nombre,
            }
          : null,

        posicion: row.posicion_nombre
          ? {
              id: safeNum(row.posicion_id),
              nombre: row.posicion_nombre,
            }
          : null,

        /*
         * Compatibilidad frontend anterior.
         */
        sucursal: sucursales[0] ?? null,

        /*
         * Nueva relación N:M.
         */
        sucursales,
      });
    }

    /*
     * Como nombre_jugador y nombre de academia están cifrados con
     * AES-GCM, MySQL no puede ordenarlos semánticamente.
     * Se conserva el comportamiento de presentación ordenando
     * después de descifrar, dentro del backend autorizado.
     */
    jugadores.sort((a, b) => {
      const nombreA = String(a?.nombre_jugador ?? "");
      const nombreB = String(b?.nombre_jugador ?? "");
      const byJugador = nombreA.localeCompare(nombreB, "es", { sensitivity: "base" });

      if (byJugador !== 0) {
        return byJugador;
      }

      const academiaA = String(a?.academia?.nombre ?? "");
      const academiaB = String(b?.academia?.nombre ?? "");
      const byAcademia = academiaA.localeCompare(academiaB, "es", { sensitivity: "base" });

      if (byAcademia !== 0) {
        return byAcademia;
      }

      const deporteA = String(a?.deporte?.nombre ?? "");
      const deporteB = String(b?.deporte?.nombre ?? "");
      const byDeporte = deporteA.localeCompare(deporteB, "es", { sensitivity: "base" });

      if (byDeporte !== 0) {
        return byDeporte;
      }

      return Number(a?.id ?? 0) - Number(b?.id ?? 0);
    });

    const academias = new Set(
      jugadores.map((jugador) => Number(jugador.academia_id)).filter((id) => Number.isInteger(id) && id > 0)
    );

    const deportes = new Set(
      jugadores.map((jugador) => Number(jugador.deporte_id)).filter((id) => Number.isInteger(id) && id > 0)
    );

    return reply.send({
      ok: true,
      count: jugadores.length,
      resumen: {
        jugadores: jugadores.length,
        academias: academias.size,
        deportes: deportes.size,
      },
      jugadores,
    });
  });

  /* =======================================================

     NUEVA API CANÓNICA POR JUGADOR_ID

  ======================================================= */

  /* -------------------------------------------------------

     GET /jugadores/id/:id/resumen

  ------------------------------------------------------- */

  app.get("/jugadores/id/:id/resumen", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);

    if (!auth) {
      return;
    }

    const db = getDb();

    if (!(await assertGuardOrReply(db, auth.rut, reply))) {
      return;
    }

    const parsed = JugadorIdParam.safeParse(req.params);

    if (!parsed.success) {
      return reply.code(400).send({
        ok: false,

        message: "BAD_REQUEST",
      });
    }

    const row = await getJugadorBaseById(db, parsed.data.id, auth.rut);

    if (!row) {
      return reply.code(403).send({
        ok: false,

        message: "FORBIDDEN",
      });
    }

    const jugador = await normalizeJugadorDetalle(db, row);

    const [statsResult, pagos] = await Promise.all([getEstadisticasJugador(db, row), getPagosJugador(db, row)]);

    return reply.send({
      ok: true,

      jugador,

      /*

       * Compatibilidad con portalDashboard anterior:

       * estadísticas planas.

       */

      estadisticas: statsResult.flat,

      /*

       * Nueva estructura multideporte.

       */

      estadisticas_joined: {
        base: statsResult.base,

        sport: statsResult.sport,
      },

      stats_id: statsResult.stats_id,

      tiene_estadisticas: statsResult.tiene_estadisticas,

      estadisticas_soportadas: statsResult.supported,

      pagos,
    });
  });

  /* -------------------------------------------------------

     GET /jugadores/id/:id/estadisticas

  ------------------------------------------------------- */

  app.get("/jugadores/id/:id/estadisticas", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);

    if (!auth) {
      return;
    }

    const db = getDb();

    if (!(await assertGuardOrReply(db, auth.rut, reply))) {
      return;
    }

    const parsed = JugadorIdParam.safeParse(req.params);

    if (!parsed.success) {
      return reply.code(400).send({
        ok: false,

        message: "BAD_REQUEST",
      });
    }

    try {
      /*

       * Seguridad:

       * academia_id y deporte_id NO vienen desde el cliente.

       *

       * Se obtienen únicamente desde el jugador que debe

       * pertenecer al RUT del apoderado autenticado.

       */

      const row = await getJugadorBaseById(db, parsed.data.id, auth.rut);

      if (!row) {
        return reply.code(403).send({
          ok: false,

          message: "FORBIDDEN",
        });
      }

      const statsResult = await getEstadisticasJugador(db, row);

      if (!statsResult.supported) {
        return reply.code(400).send({
          ok: false,

          message: "DEPORTE_NO_SOPORTADO",

          deporte_id: safeNum(row.deporte_id),
        });
      }

      return reply.send({
        ok: true,

        jugador: {
          id: safeNum(row.id),

          rut_jugador: decryptRutNumber(row.rut_jugador_enc),

          nombre_jugador: decryptText(row.nombre_jugador_enc),

          academia_id: safeNum(row.academia_id),

          deporte_id: safeNum(row.deporte_id),
        },

        academia: safeNum(row.academia_id)
          ? {
              id: safeNum(row.academia_id),

              nombre: decryptAcademiaName(row.academia_nombre_enc),
            }
          : null,

        deporte: safeNum(row.deporte_id)
          ? {
              id: safeNum(row.deporte_id),

              nombre: row.deporte_nombre ?? null,
            }
          : null,

        stats_id: statsResult.stats_id,

        tiene_estadisticas: statsResult.tiene_estadisticas,

        estadisticas: {
          base: statsResult.base,

          sport: statsResult.sport,
        },

        /*

         * También entregamos flat porque será útil

         * para widgets/KPI del nuevo portal.

         */

        flat: statsResult.flat,
      });
    } catch (error: any) {
      return reply.code(500).send({
        ok: false,

        message: "ERROR_ESTADISTICAS",

        error: error?.sqlMessage ?? error?.message ?? "DB error",
      });
    }
  });

  /* -------------------------------------------------------

     GET /jugadores/id/:id/foto

  ------------------------------------------------------- */

  app.get("/jugadores/id/:id/foto", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);

    if (!auth) {
      return;
    }

    const db = getDb();

    if (!(await assertGuardOrReply(db, auth.rut, reply))) {
      return;
    }

    const parsed = JugadorIdParam.safeParse(req.params);

    if (!parsed.success) {
      return reply.code(400).send({
        ok: false,

        message: "BAD_REQUEST",
      });
    }

    const [rows]: any[] = await db.query(
      `

            SELECT

              foto_base64,

              foto_mime

            FROM jugadores

            WHERE id = ?

              AND rut_apoderado_idx = ?

            LIMIT 1

          `,

      [parsed.data.id, rutBlindIndex(auth.rut)]
    );

    const row = rows?.[0] ?? null;

    if (!row) {
      return reply.code(403).send({
        ok: false,

        message: "FORBIDDEN",
      });
    }

    return reply.send({
      ok: true,

      foto_base64: row.foto_base64 ?? null,

      foto_mime: row.foto_mime ?? null,
    });
  });

  /* -------------------------------------------------------

     PATCH /jugadores/id/:id/foto

  ------------------------------------------------------- */

  app.patch("/jugadores/id/:id/foto", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);

    if (!auth) {
      return;
    }

    const db = getDb();

    if (!(await assertGuardOrReply(db, auth.rut, reply))) {
      return;
    }

    const parsed = JugadorIdParam.safeParse(req.params);

    if (!parsed.success) {
      return reply.code(400).send({
        ok: false,

        message: "BAD_REQUEST",
      });
    }

    const body = FotoBodySchema.safeParse(req.body);

    if (!body.success) {
      return reply.code(400).send({
        ok: false,

        message: "BAD_REQUEST",
      });
    }

    const [ownership]: any[] = await db.query(
      `

            SELECT id

            FROM jugadores

            WHERE id = ?

              AND rut_apoderado_idx = ?

            LIMIT 1

          `,

      [parsed.data.id, rutBlindIndex(auth.rut)]
    );

    if (!ownership?.length) {
      return reply.code(403).send({
        ok: false,

        message: "FORBIDDEN",
      });
    }

    const fotoBase64 = body.data.foto_base64 ? String(body.data.foto_base64).replace(/\s+/g, "") : null;

    const fotoMime = body.data.foto_mime ? String(body.data.foto_mime).toLowerCase().trim() : null;

    if (fotoBase64 == null && fotoMime == null) {
      await db.query(
        `

            UPDATE jugadores

            SET

              foto_base64 = NULL,

              foto_mime = NULL,

              foto_updated_at = NOW()

            WHERE id = ?

              AND rut_apoderado_idx = ?

            LIMIT 1

          `,

        [parsed.data.id, rutBlindIndex(auth.rut)]
      );

      return reply.send({
        ok: true,

        cleared: true,
      });
    }

    if (!fotoMime || !isValidFotoMime(fotoMime)) {
      return reply.code(400).send({
        ok: false,

        message: "FOTO_MIME_INVALIDO",
      });
    }

    if (!fotoBase64 || fotoBase64.length < 50) {
      return reply.code(400).send({
        ok: false,

        message: "FOTO_BASE64_INVALIDA",
      });
    }

    await db.query(
      `

          UPDATE jugadores

          SET

            foto_base64 = ?,

            foto_mime = ?,

            foto_updated_at = NOW()

          WHERE id = ?

            AND rut_apoderado_idx = ?

          LIMIT 1

        `,

      [fotoBase64, fotoMime, parsed.data.id, rutBlindIndex(auth.rut)]
    );

    return reply.send({
      ok: true,
    });
  });

  /* -------------------------------------------------------

     GET /jugadores/id/:id/contrato

  ------------------------------------------------------- */

  app.get("/jugadores/id/:id/contrato", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);

    if (!auth) {
      return;
    }

    const db = getDb();

    if (!(await assertGuardOrReply(db, auth.rut, reply))) {
      return;
    }

    const parsed = JugadorIdParam.safeParse(req.params);

    if (!parsed.success) {
      return reply.code(400).send({
        ok: false,

        message: "BAD_REQUEST",
      });
    }

    const [rows]: any[] = await db.query(
      `

            SELECT

              rut_jugador_enc,

              contrato_prestacion,

              contrato_prestacion_mime

            FROM jugadores

            WHERE id = ?

              AND rut_apoderado_idx = ?

            LIMIT 1

          `,

      [parsed.data.id, rutBlindIndex(auth.rut)]
    );

    const row = rows?.[0] ?? null;

    if (!row) {
      return reply.code(403).send({
        ok: false,

        message: "FORBIDDEN",
      });
    }

    if (!hasB64(row.contrato_prestacion)) {
      return reply.code(404).send({
        ok: false,

        message: "NO_CONTRATO",
      });
    }

    const mime = String(row.contrato_prestacion_mime || "application/pdf").toLowerCase();

    if (!mime.includes("application/pdf")) {
      return reply.code(415).send({
        ok: false,
        message: "UNSUPPORTED_MEDIA_TYPE",
      });
    }

    const cleaned = cleanBase64(row.contrato_prestacion);

    let buffer: Buffer;

    try {
      buffer = Buffer.from(cleaned, "base64");
    } catch {
      return reply.code(500).send({
        ok: false,

        message: "CONTRATO_INVALIDO",
      });
    }

    const MAX_BYTES = 6 * 1024 * 1024;

    if (buffer.length > MAX_BYTES) {
      return reply.code(413).send({
        ok: false,

        message: "CONTRATO_DEMASIADO_GRANDE",
      });
    }

    reply.header("Content-Type", "application/pdf");

    const contratoRut = decryptRutString(row.rut_jugador_enc) ?? "jugador";

    reply.header("Content-Disposition", `inline; filename="Contrato_${contratoRut}.pdf"`);

    reply.header("Cache-Control", "no-store, max-age=0");

    return reply.send(buffer);
  });

  /* -------------------------------------------------------

     GET /jugadores/id/:id/pagos

  ------------------------------------------------------- */

  app.get("/jugadores/id/:id/pagos", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);

    if (!auth) {
      return;
    }

    const db = getDb();

    if (!(await assertGuardOrReply(db, auth.rut, reply))) {
      return;
    }

    const parsed = JugadorIdParam.safeParse(req.params);

    if (!parsed.success) {
      return reply.code(400).send({
        ok: false,

        message: "BAD_REQUEST",
      });
    }

    const row = await getJugadorBaseById(db, parsed.data.id, auth.rut);

    if (!row) {
      return reply.code(403).send({
        ok: false,

        message: "FORBIDDEN",
      });
    }

    const pagos = await getPagosJugador(db, row);

    return reply.send({
      ok: true,

      jugador_id: parsed.data.id,

      academia_id: safeNum(row.academia_id),

      pagos,
    });
  });

  /* =======================================================

     ENDPOINTS LEGACY POR RUT

     Se mantienen para que el portal actual continúe

     funcionando mientras migramos portalDashboard.jsx.

     Cuando exista más de un registro con el mismo RUT

     para el apoderado, se exige utilizar jugador_id.

  ======================================================= */

  /* -------------------------------------------------------

     GET /jugadores/:rut/resumen

  ------------------------------------------------------- */

  app.get("/jugadores/:rut/resumen", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);

    if (!auth) {
      return;
    }

    const db = getDb();

    if (!(await assertGuardOrReply(db, auth.rut, reply))) {
      return;
    }

    const parsed = RutJugadorParam.safeParse(req.params);

    if (!parsed.success) {
      return reply.code(400).send({
        ok: false,

        message: "BAD_REQUEST",
      });
    }

    const resolved = await resolveJugadorLegacyByRut(db, parsed.data.rut, auth.rut);

    if (!resolved.ok) {
      return reply.code(resolved.code).send({
        ok: false,

        message: resolved.message,
      });
    }

    const row = await getJugadorBaseById(db, Number(resolved.jugador.id), auth.rut);

    if (!row) {
      return reply.code(404).send({
        ok: false,

        message: "NOT_FOUND",
      });
    }

    const jugador = await normalizeJugadorDetalle(db, row);

    const [statsResult, pagos] = await Promise.all([getEstadisticasJugador(db, row), getPagosJugador(db, row)]);

    return reply.send({
      ok: true,

      jugador,

      /*

       * Compatibilidad portal anterior.

       */

      estadisticas: statsResult.flat,

      /*

       * Nueva forma multideporte.

       */

      estadisticas_joined: {
        base: statsResult.base,

        sport: statsResult.sport,
      },

      stats_id: statsResult.stats_id,

      tiene_estadisticas: statsResult.tiene_estadisticas,

      estadisticas_soportadas: statsResult.supported,

      pagos,
    });
  });

  /* -------------------------------------------------------

     GET /jugadores/:rut/foto

  ------------------------------------------------------- */

  app.get("/jugadores/:rut/foto", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);

    if (!auth) {
      return;
    }

    const db = getDb();

    if (!(await assertGuardOrReply(db, auth.rut, reply))) {
      return;
    }

    const parsed = RutJugadorParam.safeParse(req.params);

    if (!parsed.success) {
      return reply.code(400).send({
        ok: false,

        message: "BAD_REQUEST",
      });
    }

    const resolved = await resolveJugadorLegacyByRut(db, parsed.data.rut, auth.rut);

    if (!resolved.ok) {
      return reply.code(resolved.code).send({
        ok: false,

        message: resolved.message,
      });
    }

    const [rows]: any[] = await db.query(
      `

            SELECT

              foto_base64,

              foto_mime

            FROM jugadores

            WHERE id = ?

              AND rut_apoderado_idx = ?

            LIMIT 1

          `,

      [Number(resolved.jugador.id), rutBlindIndex(auth.rut)]
    );

    const row = rows?.[0] ?? null;

    if (!row) {
      return reply.code(404).send({
        ok: false,

        message: "NOT_FOUND",
      });
    }

    return reply.send({
      ok: true,

      foto_base64: row.foto_base64 ?? null,

      foto_mime: row.foto_mime ?? null,
    });
  });

  /* -------------------------------------------------------

     PATCH /jugadores/:rut/foto

  ------------------------------------------------------- */

  app.patch("/jugadores/:rut/foto", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);

    if (!auth) {
      return;
    }

    const db = getDb();

    if (!(await assertGuardOrReply(db, auth.rut, reply))) {
      return;
    }

    const parsed = RutJugadorParam.safeParse(req.params);

    if (!parsed.success) {
      return reply.code(400).send({
        ok: false,

        message: "BAD_REQUEST",
      });
    }

    const body = FotoBodySchema.safeParse(req.body);

    if (!body.success) {
      return reply.code(400).send({
        ok: false,

        message: "BAD_REQUEST",
      });
    }

    const resolved = await resolveJugadorLegacyByRut(db, parsed.data.rut, auth.rut);

    if (!resolved.ok) {
      return reply.code(resolved.code).send({
        ok: false,

        message: resolved.message,
      });
    }

    const jugadorId = Number(resolved.jugador.id);

    const fotoBase64 = body.data.foto_base64 ? String(body.data.foto_base64).replace(/\s+/g, "") : null;

    const fotoMime = body.data.foto_mime ? String(body.data.foto_mime).toLowerCase().trim() : null;

    if (fotoBase64 == null && fotoMime == null) {
      await db.query(
        `

            UPDATE jugadores

            SET

              foto_base64 = NULL,

              foto_mime = NULL,

              foto_updated_at = NOW()

            WHERE id = ?

              AND rut_apoderado_idx = ?

            LIMIT 1

          `,

        [jugadorId, rutBlindIndex(auth.rut)]
      );

      return reply.send({
        ok: true,

        cleared: true,
      });
    }

    if (!fotoMime || !isValidFotoMime(fotoMime)) {
      return reply.code(400).send({
        ok: false,

        message: "FOTO_MIME_INVALIDO",
      });
    }

    if (!fotoBase64 || fotoBase64.length < 50) {
      return reply.code(400).send({
        ok: false,

        message: "FOTO_BASE64_INVALIDA",
      });
    }

    await db.query(
      `

          UPDATE jugadores

          SET

            foto_base64 = ?,

            foto_mime = ?,

            foto_updated_at = NOW()

          WHERE id = ?

            AND rut_apoderado_idx = ?

          LIMIT 1

        `,

      [fotoBase64, fotoMime, jugadorId, rutBlindIndex(auth.rut)]
    );

    return reply.send({
      ok: true,
    });
  });

  /* -------------------------------------------------------

     GET /jugadores/:rut/contrato

  ------------------------------------------------------- */

  app.get("/jugadores/:rut/contrato", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);

    if (!auth) {
      return;
    }

    const db = getDb();

    if (!(await assertGuardOrReply(db, auth.rut, reply))) {
      return;
    }

    const parsed = RutJugadorParam.safeParse(req.params);

    if (!parsed.success) {
      return reply.code(400).send({
        ok: false,

        message: "BAD_REQUEST",
      });
    }

    const resolved = await resolveJugadorLegacyByRut(db, parsed.data.rut, auth.rut);

    if (!resolved.ok) {
      return reply.code(resolved.code).send({
        ok: false,

        message: resolved.message,
      });
    }

    const [rows]: any[] = await db.query(
      `

            SELECT

              rut_jugador_enc,

              contrato_prestacion,

              contrato_prestacion_mime

            FROM jugadores

            WHERE id = ?

              AND rut_apoderado_idx = ?

            LIMIT 1

          `,

      [Number(resolved.jugador.id), rutBlindIndex(auth.rut)]
    );

    const row = rows?.[0] ?? null;

    if (!row) {
      return reply.code(404).send({
        ok: false,

        message: "NOT_FOUND",
      });
    }

    if (!hasB64(row.contrato_prestacion)) {
      return reply.code(404).send({
        ok: false,

        message: "NO_CONTRATO",
      });
    }

    const mime = String(row.contrato_prestacion_mime || "application/pdf").toLowerCase();

    if (!mime.includes("application/pdf")) {
      return reply.code(415).send({
        ok: false,

        message: "UNSUPPORTED_MEDIA_TYPE",
      });
    }

    const cleaned = cleanBase64(row.contrato_prestacion);

    let buffer: Buffer;

    try {
      buffer = Buffer.from(cleaned, "base64");
    } catch {
      return reply.code(500).send({
        ok: false,

        message: "CONTRATO_INVALIDO",
      });
    }

    const MAX_BYTES = 6 * 1024 * 1024;

    if (buffer.length > MAX_BYTES) {
      return reply.code(413).send({
        ok: false,

        message: "CONTRATO_DEMASIADO_GRANDE",
      });
    }

    reply.header("Content-Type", "application/pdf");

    const contratoRut = decryptRutString(row.rut_jugador_enc) ?? "jugador";

    reply.header("Content-Disposition", `inline; filename="Contrato_${contratoRut}.pdf"`);

    reply.header("Cache-Control", "no-store, max-age=0");

    return reply.send(buffer);
  });

  /* -------------------------------------------------------

     GET /jugadores/:rut/pagos

  ------------------------------------------------------- */

  app.get("/jugadores/:rut/pagos", async (req, reply) => {
    const auth = getApoderadoAuth(req, reply);

    if (!auth) {
      return;
    }

    const db = getDb();

    if (!(await assertGuardOrReply(db, auth.rut, reply))) {
      return;
    }

    const parsed = RutJugadorParam.safeParse(req.params);

    if (!parsed.success) {
      return reply.code(400).send({
        ok: false,

        message: "BAD_REQUEST",
      });
    }

    const resolved = await resolveJugadorLegacyByRut(db, parsed.data.rut, auth.rut);

    if (!resolved.ok) {
      return reply.code(resolved.code).send({
        ok: false,

        message: resolved.message,
      });
    }

    const row = await getJugadorBaseById(db, Number(resolved.jugador.id), auth.rut);

    if (!row) {
      return reply.code(404).send({
        ok: false,

        message: "NOT_FOUND",
      });
    }

    const pagos = await getPagosJugador(db, row);

    return reply.send({
      ok: true,

      pagos,
    });
  });
}
