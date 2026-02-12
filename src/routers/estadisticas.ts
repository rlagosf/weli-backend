// src/routes/estadisticas.ts
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db";
import {
  requireAuth,
  requireRoles,
  // ✅ opción 2 exportada (estándar WELI)
  getEffectiveAcademiaId,
} from "../middlewares/authz";

/* ─────────────────── Schemas ─────────────────── */

const IdParam = z.object({ id: z.string().regex(/^\d+$/, "ID inválido") });

const RutParam = z.object({
  rut: z.string().regex(/^\d{7,8}$/, "RUT inválido (7 u 8 dígitos sin DV)"),
});

const JugadorIdParam = z.object({
  jugador_id: z.string().regex(/^\d+$/, "jugador_id inválido"),
});

const PageQuery = z.object({
  limit: z.coerce.number().int().positive().max(200).optional().default(50),
  offset: z.coerce.number().int().nonnegative().optional().default(0),

  // ✅ se acepta por compat, pero se valida contra effectiveAcademiaId
  academia_id: z.coerce.number().int().positive().optional(),

  deporte_id: z.coerce.number().int().positive().optional(),
  jugador_id: z.coerce.number().int().positive().optional(),
});

// ✅ agregado global (SUM) por deporte, opcional partido
const AggregateQuery = z.object({
  // ✅ se acepta por compat, pero se valida contra effectiveAcademiaId
  academia_id: z.coerce.number().int().positive().optional(),

  deporte_id: z.coerce.number().int().positive(), // requerido

  partido_id: z
    .union([z.coerce.number().int().positive(), z.literal("null"), z.null()])
    .optional(),
});

const CreateSchema = z
  .object({
    // ✅ se acepta por compat, pero se valida contra effectiveAcademiaId
    academia_id: z.coerce.number().int().positive(),
    deporte_id: z.coerce.number().int().positive(),
    jugador_id: z.coerce.number().int().positive(),
    partido_id: z.coerce.number().int().positive().nullable().optional(),
  })
  .passthrough();

const UpdateSchema = z.object({}).passthrough();

/* ─────────────────── Helpers ─────────────────── */

const sqlErr = (err: any) => err?.sqlMessage || err?.message || "DB error";

// mapping deporte_id -> tabla detalle
const SPORT_TABLE: Record<number, string> = {
  1: "stats_futbol",
  2: "stats_voley",
  3: "stats_tenis",
  4: "stats_padel",
  5: "stats_tenis_mesa",
  6: "stats_basquet",
};

// Campos base comunes (stats_base)
const baseKeys = new Set([
  "minutos_jugados",
  "partidos_jugados",
  "lesiones",
  "dias_baja",
  "sanciones_federativas",
]);

/**
 * ✅ Whitelist por deporte (detalle)
 */
const allowedSportKeys: Record<number, Set<string>> = {
  1: new Set([
    "goles",
    "asistencias",
    "tiros_libres",
    "penales",
    "tarjetas_amarillas",
    "tarjetas_rojas",
    "tiros_arco",
    "tiros_fuera",
    "tiros_bloqueados",
    "regates_exitosos",
    "centros_acertados",
    "pases_clave",
    "intercepciones",
    "despejes",
    "duelos_ganados",
    "entradas_exitosas",
    "bloqueos",
    "recuperaciones",
    "pases_completados",
    "pases_errados",
    "posesion_perdida",
    "offsides",
    "faltas_cometidas",
    "faltas_recibidas",
    "distancia_recorrida_km",
    "sprints",
    "duelos_aereos_ganados",
    "torneos_convocados",
    "titular_partidos",
  ]),
  2: new Set([
    "ataque_intentos",
    "ataque_puntos",
    "ataque_errores",
    "saques_total",
    "saques_aces",
    "saques_positivos",
    "saques_errores",
    "bloqueos_punto",
    "bloqueos_toques",
    "recepciones_total",
    "recepcion_positiva",
    "recepcion_perfecta",
    "defensas_recuperadas",
    "armados_total",
    "armados_precision",
    "sideout_pct",
    "breakpoints_pct",
    "errores_totales",
  ]),
  3: new Set([
    "primer_servicio_pct",
    "puntos_primer_servicio",
    "puntos_segundo_servicio",
    "aces",
    "dobles_faltas",
    "break_points_oportunidades",
    "break_points_convertidos",
    "winners",
    "errores_no_forzados",
    "peloteos_cortos_ganados",
    "puntos_ganados_total",
    "juegos_ganados_total",
  ]),
  4: new Set([
    "primer_saque_pct",
    "puntos_primer_saque",
    "puntos_segundo_saque",
    "puntos_oro_jugados",
    "puntos_oro_ganados",
    "puntos_oro_ganados_con_saque",
    "errores_no_forzados",
    "errores_forzados",
    "winners",
    "tiempo_red_pct",
    "tiempo_fondo_pct",
    "puntos_red_ganados",
    "voleas_total",
    "voleas_ganadoras",
    "voleas_errores",
    "remates_total",
    "remates_ganadores",
    "remates_errores",
  ]),
  5: new Set([
    "efectividad_servicio_pct",
    "efectividad_devolucion_pct",
    "errores_no_forzados",
    "winners",
    "primer_saque_pct",
    "puntos_presion_jugados",
    "puntos_presion_ganados",
    "dobles_puntos_jugados",
    "dobles_puntos_ganados",
    "fc_media",
    "fc_max",
    "lactato",
  ]),
  6: new Set([
    "puntos",
    "rebotes_ofensivos",
    "rebotes_defensivos",
    "asistencias",
    "robos",
    "bloqueos",
    "perdidas",
    "faltas",
    "ts_pct",
    "efg_pct",
    "usg_pct",
    "plus_minus",
    "pir",
    "per",
  ]),
};

const floatKeys = new Set([
  "distancia_recorrida_km",
  "sideout_pct",
  "breakpoints_pct",
  "primer_servicio_pct",
  "primer_saque_pct",
  "efectividad_servicio_pct",
  "efectividad_devolucion_pct",
  "tiempo_red_pct",
  "tiempo_fondo_pct",
  "ts_pct",
  "efg_pct",
  "usg_pct",
  "pir",
  "per",
  "lactato",
]);

function coerceNumbers(obj: Record<string, any>) {
  const out: Record<string, any> = { ...obj };

  for (const [k, v] of Object.entries(out)) {
    if (v === null || v === undefined || v === "") continue;

    if (floatKeys.has(k)) {
      const n = Number.parseFloat(String(v));
      out[k] = Number.isFinite(n) ? n : 0;
    } else {
      const n = Number.parseInt(String(v), 10);
      if (Number.isFinite(n)) out[k] = n;
    }
  }
  return out;
}

function pickBaseAndSport(
  deporte_id: number,
  raw: Record<string, any>
): { base: Record<string, any>; sport: Record<string, any>; rejected: string[] } {
  const sportSet = allowedSportKeys[deporte_id] ?? new Set<string>();
  const base: Record<string, any> = {};
  const sport: Record<string, any> = {};
  const rejected: string[] = [];

  for (const [k, v] of Object.entries(raw)) {
    if (baseKeys.has(k)) base[k] = v;
    else if (sportSet.has(k)) sport[k] = v;
    else rejected.push(k);
  }

  return { base, sport, rejected };
}

function normalizePartidoId(v: any): number | null | undefined {
  // undefined => no viene (default acumulado)
  // null => acumulado
  // number => partido específico
  if (v === undefined) return undefined;
  if (v === null || v === "null") return null;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

function assertQueryAcademiaMatchesEffectiveOr403(
  academia_id: number | undefined,
  effective: number,
  reply: any
) {
  if (academia_id !== undefined && Number(academia_id) !== Number(effective)) {
    reply.code(403).send({ ok: false, message: "ACADEMIA_SCOPE_MISMATCH" });
    return false;
  }
  return true;
}

async function getJugadorScopeInAcademia(jugador_id: number, academia_id: number) {
  const [rows]: any = await db.query(
    "SELECT id, academia_id, deporte_id FROM jugadores WHERE id = ? AND academia_id = ? LIMIT 1",
    [jugador_id, academia_id]
  );
  const j = rows?.[0];
  if (!j) return null;

  return {
    jugador_id: Number(j.id),
    academia_id: Number(j.academia_id),
    deporte_id: Number(j.deporte_id),
  };
}

async function ensureStatsBase(
  academia_id: number,
  deporte_id: number,
  jugador_id: number,
  partido_id: number | null
): Promise<number> {
  await db.query(
    `
    INSERT INTO stats_base (academia_id, deporte_id, jugador_id, partido_id)
    VALUES (?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP
    `,
    [academia_id, deporte_id, jugador_id, partido_id]
  );

  const [rows]: any = await db.query(
    `
    SELECT id FROM stats_base
     WHERE academia_id = ? AND deporte_id = ? AND jugador_id = ? AND
           ( (partido_id IS NULL AND ? IS NULL) OR (partido_id = ?) )
     LIMIT 1
    `,
    [academia_id, deporte_id, jugador_id, partido_id, partido_id]
  );

  const id = rows?.[0]?.id;
  if (!id) throw new Error("STATS_BASE_NOT_FOUND_AFTER_UPSERT");
  return Number(id);
}

async function ensureSportRow(deporte_id: number, stats_id: number) {
  const table = SPORT_TABLE[deporte_id];
  if (!table) throw new Error("DEPORTE_NO_SOPORTADO");

  await db.query(
    `
    INSERT INTO \`${table}\` (stats_id)
    VALUES (?)
    ON DUPLICATE KEY UPDATE stats_id = stats_id
    `,
    [stats_id]
  );
}

async function getJoinedStatsByStatsIdScoped(stats_id: number, academia_id: number) {
  const [baseRows]: any = await db.query(
    "SELECT * FROM stats_base WHERE id = ? AND academia_id = ? LIMIT 1",
    [stats_id, academia_id]
  );
  const base = baseRows?.[0];
  if (!base) return null;

  const deporte_id = Number(base.deporte_id);
  const table = SPORT_TABLE[deporte_id];
  if (!table) return { base, sport: null };

  const [sportRows]: any = await db.query(`SELECT * FROM \`${table}\` WHERE stats_id = ? LIMIT 1`, [stats_id]);
  return { base, sport: sportRows?.[0] ?? null };
}

async function getJoinedStatsByJugadorIdScoped(jugador_id: number, academia_id: number) {
  const scope = await getJugadorScopeInAcademia(jugador_id, academia_id);
  if (!scope) return null;

  const stats_id = await ensureStatsBase(scope.academia_id, scope.deporte_id, scope.jugador_id, null);
  await ensureSportRow(scope.deporte_id, stats_id);

  return await getJoinedStatsByStatsIdScoped(stats_id, academia_id);
}

function buildSportJoinAndSelect(deporte_id?: number) {
  if (!deporte_id || !SPORT_TABLE[deporte_id]) return { joinSql: "", selectColsSql: "" };

  const table = SPORT_TABLE[deporte_id];
  const sportKeys = allowedSportKeys[deporte_id] ?? new Set<string>();

  const joinSql = `LEFT JOIN \`${table}\` sd ON sd.stats_id = sb.id`;
  const cols = [...sportKeys].map((k) => `sd.\`${k}\` AS \`${k}\``).join(", ");
  const selectColsSql = cols ? `, ${cols}` : "";

  return { joinSql, selectColsSql };
}

/* ─────────────────── Router ─────────────────── */

export default async function estadisticas(app: FastifyInstance) {
  /**
   * ✅ Mantener matriz:
   * - READ: 1/2/3
   * - WRITE: 1/3
   */
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  app.get("/health", { preHandler: canRead }, async (_req, reply) => {
    reply.header("Cache-Control", "no-store");
    return { module: "estadisticas", status: "ready", timestamp: new Date().toISOString() };
  });

  // (Opcional) Debug auth — se mantiene, pero cuidado en prod
  app.get("/debug/whoami", { preHandler: canRead }, async (req: any, reply) => {
    return reply.send({ ok: true, user: req.user ?? null, auth: req.auth ?? null });
  });

  /**
   * ✅ AGGREGATE (SUM) — SIEMPRE scope por academia efectiva
   */
  app.get("/aggregate", { preHandler: canRead }, async (req, reply) => {
    const parsed = AggregateQuery.safeParse((req as any).query);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Query inválida", errors: parsed.error.flatten() });
    }

    let academiaId: number;
    try {
      academiaId = getEffectiveAcademiaId(req as any);
    } catch (e: any) {
      return reply.code(e?.statusCode ?? 403).send({ ok: false, message: e?.message ?? "FORBIDDEN" });
    }

    if (!assertQueryAcademiaMatchesEffectiveOr403(parsed.data.academia_id, academiaId, reply)) return;

    const { deporte_id } = parsed.data;
    const table = SPORT_TABLE[deporte_id];
    if (!table) return reply.code(400).send({ ok: false, message: "DEPORTE_NO_SOPORTADO" });

    const partido_id = normalizePartidoId((parsed.data as any).partido_id);

    const where: string[] = ["sb.deporte_id = ?", "sb.academia_id = ?"];
    const params: any[] = [deporte_id, academiaId];

    // default acumulado si no mandan partido_id
    if (partido_id === undefined || partido_id === null) where.push("sb.partido_id IS NULL");
    else {
      where.push("sb.partido_id = ?");
      params.push(partido_id);
    }

    const whereSql = `WHERE ${where.join(" AND ")}`;
    const sportKeys = allowedSportKeys[deporte_id] ?? new Set<string>();

    const baseSumCols = [...baseKeys].map((k) => `SUM(COALESCE(sb.\`${k}\`,0)) AS \`${k}\``).join(", ");
    const sportSumCols = [...sportKeys].map((k) => `SUM(COALESCE(sd.\`${k}\`,0)) AS \`${k}\``).join(", ");

    try {
      const [rows]: any = await db.query(
        `
        SELECT
          COUNT(*) AS rows_base,
          SUM(CASE WHEN sd.stats_id IS NULL THEN 1 ELSE 0 END) AS rows_detail_missing,
          ${baseSumCols}
          ${sportSumCols ? `, ${sportSumCols}` : ""}
        FROM stats_base sb
        LEFT JOIN \`${table}\` sd ON sd.stats_id = sb.id
        ${whereSql}
        `,
        params
      );

      const r = rows?.[0] ?? {};
      const totals: Record<string, number> = {};

      for (const k of [...baseKeys, ...sportKeys]) {
        const n = Number(r?.[k] ?? 0);
        totals[k] = Number.isFinite(n) ? n : 0;
      }

      return reply.send({
        ok: true,
        scope: {
          academia_id: academiaId,
          deporte_id,
          partido_id: partido_id ?? null,
          table,
        },
        meta: {
          rows_base: Number(r?.rows_base ?? 0) || 0,
          rows_detail_missing: Number(r?.rows_detail_missing ?? 0) || 0,
        },
        totals,
      });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al agregar estadísticas", error: sqlErr(err) });
    }
  });

  /**
   * ✅ REPAIR faltantes — SIEMPRE scope por academia efectiva
   */
  app.get("/repair-missing", { preHandler: canWrite }, async (req, reply) => {
    const parsed = AggregateQuery.safeParse((req as any).query);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Query inválida", errors: parsed.error.flatten() });
    }

    let academiaId: number;
    try {
      academiaId = getEffectiveAcademiaId(req as any);
    } catch (e: any) {
      return reply.code(e?.statusCode ?? 403).send({ ok: false, message: e?.message ?? "FORBIDDEN" });
    }

    if (!assertQueryAcademiaMatchesEffectiveOr403(parsed.data.academia_id, academiaId, reply)) return;

    const { deporte_id } = parsed.data;
    const table = SPORT_TABLE[deporte_id];
    if (!table) return reply.code(400).send({ ok: false, message: "DEPORTE_NO_SOPORTADO" });

    const where: string[] = ["sb.deporte_id = ?", "sb.academia_id = ?", "sb.partido_id IS NULL"];
    const params: any[] = [deporte_id, academiaId];
    const whereSql = `WHERE ${where.join(" AND ")}`;

    try {
      const [missing]: any = await db.query(
        `
        SELECT sb.id AS stats_id
        FROM stats_base sb
        LEFT JOIN \`${table}\` sd ON sd.stats_id = sb.id
        ${whereSql}
          AND sd.stats_id IS NULL
        LIMIT 5000
        `,
        params
      );

      const ids = (missing || [])
        .map((x: any) => Number(x.stats_id))
        .filter((n: number) => Number.isFinite(n) && n > 0);

      for (const id of ids) await ensureSportRow(deporte_id, id);

      return reply.send({ ok: true, deporte_id, academia_id: academiaId, repaired: ids.length });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al reparar faltantes", error: sqlErr(err) });
    }
  });

  /**
   * ✅ LISTADO (paginado) desde stats_base (acumulado por defecto: partido_id NULL)
   * SIEMPRE scope por academia efectiva
   */
  app.get("/", { preHandler: canRead }, async (req, reply) => {
    const parsed = PageQuery.safeParse((req as any).query);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Query inválida", errors: parsed.error.flatten() });
    }

    let academiaId: number;
    try {
      academiaId = getEffectiveAcademiaId(req as any);
    } catch (e: any) {
      return reply.code(e?.statusCode ?? 403).send({ ok: false, message: e?.message ?? "FORBIDDEN" });
    }

    if (!assertQueryAcademiaMatchesEffectiveOr403(parsed.data.academia_id, academiaId, reply)) return;

    const { limit, offset, deporte_id, jugador_id } = parsed.data;

    const where: string[] = ["sb.partido_id IS NULL", "sb.academia_id = ?"];
    const params: any[] = [academiaId];

    if (deporte_id) {
      where.push("sb.deporte_id = ?");
      params.push(deporte_id);
    }
    if (jugador_id) {
      where.push("sb.jugador_id = ?");
      params.push(jugador_id);
    }

    const whereSql = `WHERE ${where.join(" AND ")}`;
    const { joinSql, selectColsSql } = buildSportJoinAndSelect(deporte_id);

    try {
      const [rows]: any = await db.query(
        `
        SELECT
          sb.id AS stats_id,
          sb.academia_id,
          sb.deporte_id,
          sb.jugador_id,
          sb.minutos_jugados,
          sb.partidos_jugados,
          sb.lesiones,
          sb.dias_baja,
          sb.sanciones_federativas,
          j.nombre_jugador,
          j.rut_jugador
          ${selectColsSql}
        FROM stats_base sb
        JOIN jugadores j ON j.id = sb.jugador_id AND j.academia_id = sb.academia_id
        ${joinSql}
        ${whereSql}
        ORDER BY sb.id DESC
        LIMIT ? OFFSET ?
        `,
        [...params, limit, offset]
      );

      return reply.send({
        ok: true,
        items: rows,
        limit,
        offset,
        joined_sport: Boolean(deporte_id && SPORT_TABLE[deporte_id]),
        note: deporte_id ? undefined : "Para incluir métricas del deporte, envía deporte_id (1..6).",
      });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al listar", error: sqlErr(err) });
    }
  });

  /**
   * ✅ Alias /joined (misma lógica que "/")
   */
  app.get("/joined", { preHandler: canRead }, async (req, reply) => {
    // simplemente reusa el handler de arriba duplicando lo mínimo (Fastify no expone fácil el handler)
    const parsed = PageQuery.safeParse((req as any).query);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Query inválida", errors: parsed.error.flatten() });
    }

    let academiaId: number;
    try {
      academiaId = getEffectiveAcademiaId(req as any);
    } catch (e: any) {
      return reply.code(e?.statusCode ?? 403).send({ ok: false, message: e?.message ?? "FORBIDDEN" });
    }

    if (!assertQueryAcademiaMatchesEffectiveOr403(parsed.data.academia_id, academiaId, reply)) return;

    const { limit, offset, deporte_id, jugador_id } = parsed.data;

    const where: string[] = ["sb.partido_id IS NULL", "sb.academia_id = ?"];
    const params: any[] = [academiaId];

    if (deporte_id) {
      where.push("sb.deporte_id = ?");
      params.push(deporte_id);
    }
    if (jugador_id) {
      where.push("sb.jugador_id = ?");
      params.push(jugador_id);
    }

    const whereSql = `WHERE ${where.join(" AND ")}`;
    const { joinSql, selectColsSql } = buildSportJoinAndSelect(deporte_id);

    try {
      const [rows]: any = await db.query(
        `
        SELECT
          sb.id AS stats_id,
          sb.academia_id,
          sb.deporte_id,
          sb.jugador_id,
          sb.minutos_jugados,
          sb.partidos_jugados,
          sb.lesiones,
          sb.dias_baja,
          sb.sanciones_federativas,
          j.nombre_jugador,
          j.rut_jugador
          ${selectColsSql}
        FROM stats_base sb
        JOIN jugadores j ON j.id = sb.jugador_id AND j.academia_id = sb.academia_id
        ${joinSql}
        ${whereSql}
        ORDER BY sb.id DESC
        LIMIT ? OFFSET ?
        `,
        [...params, limit, offset]
      );

      return reply.send({ ok: true, items: rows, limit, offset, joined_sport: Boolean(deporte_id && SPORT_TABLE[deporte_id]) });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al listar (joined)", error: sqlErr(err) });
    }
  });

  /**
   * ✅ Conveniencia por jugador_id (SIEMPRE scope por academia efectiva)
   */
  app.get("/by-jugador/:jugador_id", { preHandler: canRead }, async (req, reply) => {
    const p = JugadorIdParam.safeParse((req as any).params);
    if (!p.success) return reply.code(400).send({ ok: false, message: "jugador_id inválido" });

    let academiaId: number;
    try {
      academiaId = getEffectiveAcademiaId(req as any);
    } catch (e: any) {
      return reply.code(e?.statusCode ?? 403).send({ ok: false, message: e?.message ?? "FORBIDDEN" });
    }

    const jugador_id = Number(p.data.jugador_id);

    try {
      const joined = await getJoinedStatsByJugadorIdScoped(jugador_id, academiaId);
      if (!joined) return reply.code(404).send({ ok: false, message: "Jugador no encontrado" });

      return reply.send({ ok: true, item: joined });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al obtener por jugador", error: sqlErr(err) });
    }
  });

  /**
   * ✅ Conveniencia por RUT (SIEMPRE scope por academia efectiva)
   */
  app.get("/by-rut/:rut", { preHandler: canRead }, async (req, reply) => {
    const parsed = RutParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: parsed.error.issues[0]?.message });

    let academiaId: number;
    try {
      academiaId = getEffectiveAcademiaId(req as any);
    } catch (e: any) {
      return reply.code(e?.statusCode ?? 403).send({ ok: false, message: e?.message ?? "FORBIDDEN" });
    }

    const rut = parsed.data.rut;

    try {
      const [rows]: any = await db.query(
        "SELECT id AS jugador_id FROM jugadores WHERE rut_jugador = ? AND academia_id = ? LIMIT 1",
        [rut, academiaId]
      );

      const jugador_id = rows?.[0]?.jugador_id ? Number(rows[0].jugador_id) : null;
      if (!jugador_id) return reply.code(404).send({ ok: false, message: "Jugador no encontrado" });

      const joined = await getJoinedStatsByJugadorIdScoped(jugador_id, academiaId);
      return reply.send({ ok: true, item: joined });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al obtener por RUT", error: sqlErr(err) });
    }
  });

  /**
   * ✅ POST /estadisticas (WRITE: 1/3) — SIEMPRE scope por academia efectiva
   */
  app.post("/", { preHandler: canWrite }, async (req, reply) => {
    const parsed = CreateSchema.safeParse((req as any).body);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Payload inválido", errors: parsed.error.flatten() });
    }

    let academiaId: number;
    try {
      academiaId = getEffectiveAcademiaId(req as any);
    } catch (e: any) {
      return reply.code(e?.statusCode ?? 403).send({ ok: false, message: e?.message ?? "FORBIDDEN" });
    }

    // ✅ NO confiar en academia_id del body: validar que calce
    if (Number(parsed.data.academia_id) !== Number(academiaId)) {
      return reply.code(403).send({ ok: false, message: "ACADEMIA_SCOPE_MISMATCH" });
    }

    const body = (req as any).body || {};
    const raw = coerceNumbers(body);

    const deporte_id = Number(parsed.data.deporte_id);
    const jugador_id = Number(parsed.data.jugador_id);
    const partido_id = parsed.data.partido_id ?? null;

    const table = SPORT_TABLE[deporte_id];
    if (!table) return reply.code(400).send({ ok: false, message: "DEPORTE_NO_SOPORTADO" });

    // ✅ jugador debe pertenecer a academia efectiva
    const scope = await getJugadorScopeInAcademia(jugador_id, academiaId);
    if (!scope) return reply.code(404).send({ ok: false, message: "Jugador no encontrado" });

    // ✅ deporte debe calzar con el jugador
    if (scope.deporte_id !== deporte_id) {
      return reply.code(409).send({
        ok: false,
        message: "SCOPE_MISMATCH: jugador no coincide con deporte_id enviado",
        scope,
        requested: { academia_id: academiaId, deporte_id, jugador_id },
      });
    }

    const { base, sport, rejected } = pickBaseAndSport(deporte_id, raw);

    for (const k of ["academia_id", "deporte_id", "jugador_id", "partido_id"]) {
      delete (base as any)[k];
      delete (sport as any)[k];
    }

    try {
      const stats_id = await ensureStatsBase(academiaId, deporte_id, jugador_id, partido_id);
      await ensureSportRow(deporte_id, stats_id);

      if (Object.keys(base).length) await db.query("UPDATE stats_base SET ? WHERE id = ? AND academia_id = ?", [base, stats_id, academiaId]);
      if (Object.keys(sport).length) await db.query(`UPDATE \`${table}\` SET ? WHERE stats_id = ?`, [sport, stats_id]);

      const joined = await getJoinedStatsByStatsIdScoped(stats_id, academiaId);
      return reply.code(201).send({ ok: true, stats_id, item: joined, rejected_keys: rejected });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al crear/actualizar", error: sqlErr(err) });
    }
  });

  /**
   * ✅ PUT /estadisticas/:id (WRITE: 1/3) — SIEMPRE scope por academia efectiva
   */
  app.put("/:id", { preHandler: canWrite }, async (req, reply) => {
    const pid = IdParam.safeParse((req as any).params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const stats_id = Number(pid.data.id);

    const parsedBody = UpdateSchema.safeParse((req as any).body ?? {});
    if (!parsedBody.success) {
      return reply.code(400).send({ ok: false, message: "Payload inválido", errors: parsedBody.error.flatten() });
    }

    let academiaId: number;
    try {
      academiaId = getEffectiveAcademiaId(req as any);
    } catch (e: any) {
      return reply.code(e?.statusCode ?? 403).send({ ok: false, message: e?.message ?? "FORBIDDEN" });
    }

    const raw = coerceNumbers((req as any).body || {});

    try {
      const [rows]: any = await db.query(
        "SELECT deporte_id FROM stats_base WHERE id = ? AND academia_id = ? LIMIT 1",
        [stats_id, academiaId]
      );
      const baseRow = rows?.[0];
      if (!baseRow) return reply.code(404).send({ ok: false, message: "No encontrado" });

      const deporte_id = Number(baseRow.deporte_id);
      const table = SPORT_TABLE[deporte_id];
      if (!table) return reply.code(400).send({ ok: false, message: "DEPORTE_NO_SOPORTADO" });

      const { base, sport, rejected } = pickBaseAndSport(deporte_id, raw);

      for (const k of ["academia_id", "deporte_id", "jugador_id", "partido_id"]) {
        delete (base as any)[k];
        delete (sport as any)[k];
      }

      if (!Object.keys(base).length && !Object.keys(sport).length) {
        return reply.code(400).send({
          ok: false,
          message: "No hay campos válidos para actualizar (ver rejected_keys).",
          rejected_keys: rejected,
        });
      }

      await ensureSportRow(deporte_id, stats_id);

      if (Object.keys(base).length) {
        await db.query("UPDATE stats_base SET ? WHERE id = ? AND academia_id = ?", [base, stats_id, academiaId]);
      }
      if (Object.keys(sport).length) {
        await db.query(`UPDATE \`${table}\` SET ? WHERE stats_id = ?`, [sport, stats_id]);
      }

      const joined = await getJoinedStatsByStatsIdScoped(stats_id, academiaId);
      return reply.send({ ok: true, stats_id, item: joined, rejected_keys: rejected });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al actualizar", error: sqlErr(err) });
    }
  });

  /**
   * ✅ DELETE /estadisticas/:id (WRITE: 1/3) — SIEMPRE scope por academia efectiva
   */
  app.delete("/:id", { preHandler: canWrite }, async (req, reply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const stats_id = Number(parsed.data.id);

    let academiaId: number;
    try {
      academiaId = getEffectiveAcademiaId(req as any);
    } catch (e: any) {
      return reply.code(e?.statusCode ?? 403).send({ ok: false, message: e?.message ?? "FORBIDDEN" });
    }

    try {
      const [result]: any = await db.query("DELETE FROM stats_base WHERE id = ? AND academia_id = ?", [stats_id, academiaId]);
      if (Number(result?.affectedRows ?? 0) === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, deleted: stats_id });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al eliminar", error: sqlErr(err) });
    }
  });

  /**
   * ✅ GET /estadisticas/:id (READ: 1/2/3) — SIEMPRE scope por academia efectiva
   * (al final para no pisar /aggregate, /joined, /by-*)
   */
  app.get("/:id", { preHandler: canRead }, async (req, reply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const stats_id = Number(parsed.data.id);

    let academiaId: number;
    try {
      academiaId = getEffectiveAcademiaId(req as any);
    } catch (e: any) {
      return reply.code(e?.statusCode ?? 403).send({ ok: false, message: e?.message ?? "FORBIDDEN" });
    }

    try {
      const joined = await getJoinedStatsByStatsIdScoped(stats_id, academiaId);
      if (!joined) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, item: joined });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al obtener", error: sqlErr(err) });
    }
  });
}
