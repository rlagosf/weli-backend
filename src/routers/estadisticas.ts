// src/routes/estadisticas.ts
import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

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
  academia_id: z.coerce.number().int().positive().optional(),
  deporte_id: z.coerce.number().int().positive().optional(),
  jugador_id: z.coerce.number().int().positive().optional(),
});

// Base para crear/asegurar stats acumuladas del jugador
const CreateSchema = z
  .object({
    academia_id: z.coerce.number().int().positive(),
    deporte_id: z.coerce.number().int().positive(),
    jugador_id: z.coerce.number().int().positive(),
    // futuro: partido/fecha si lo necesitas (no obligatorio ahora)
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

// Whitelist por deporte (detalle)
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
    "primer_servicio_pct",
    "saques_ganadores",
    "puntos_primer_saque",
    "saque_dir_t",
    "saque_dir_cristal",
    "resto_paralelo",
    "resto_cruzado",
    "resto_globo",
    "resto_directo",
    "voleas_ganadoras_pct",
    "errores_volea_no_forzados",
    "remates_ganadores_pct",
    "puntos_oro_jugados",
    "puntos_oro_ganados",
    "errores_no_forzados",
    "golpes_ganadores",
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

// floats (lo demás int)
const floatKeys = new Set([
  "distancia_recorrida_km",
  "sideout_pct",
  "breakpoints_pct",
  "primer_servicio_pct",
  "voleas_ganadoras_pct",
  "remates_ganadores_pct",
  "efectividad_servicio_pct",
  "efectividad_devolucion_pct",
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

async function getJugadorScope(jugador_id: number) {
  const [rows]: any = await db.query(
    "SELECT id, academia_id, deporte_id FROM jugadores WHERE id = ? LIMIT 1",
    [jugador_id]
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
  // acumulado: partido_id NULL por defecto
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

async function getJoinedStatsByStatsId(stats_id: number) {
  const [baseRows]: any = await db.query("SELECT * FROM stats_base WHERE id = ? LIMIT 1", [stats_id]);
  const base = baseRows?.[0];
  if (!base) return null;

  const deporte_id = Number(base.deporte_id);
  const table = SPORT_TABLE[deporte_id];
  if (!table) return { base, sport: null };

  const [sportRows]: any = await db.query(`SELECT * FROM \`${table}\` WHERE stats_id = ? LIMIT 1`, [stats_id]);
  return { base, sport: sportRows?.[0] ?? null };
}

async function getJoinedStatsByJugadorId(jugador_id: number) {
  const scope = await getJugadorScope(jugador_id);
  if (!scope) return null;

  const stats_id = await ensureStatsBase(scope.academia_id, scope.deporte_id, scope.jugador_id, null);
  await ensureSportRow(scope.deporte_id, stats_id);

  return await getJoinedStatsByStatsId(stats_id);
}

/* ─────────────────── Router ─────────────────── */

export default async function estadisticas(app: FastifyInstance) {
  /**
   * ✅ ESTÁNDAR WELI:
   * - READ: roles 1/2/3
   * - WRITE: roles 1 y 3
   */
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  // Health
  app.get("/health", { preHandler: canRead }, async () => ({
    module: "estadisticas",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // Debug auth (solo lectura)
  app.get("/debug/whoami", { preHandler: canRead }, async (req: any, reply) => {
    return reply.send({
      ok: true,
      user: req.user ?? null,
    });
  });

  /**
   * ✅ LISTADO (paginado) desde stats_base (acumulado por defecto: partido_id NULL)
   * filtros: academia_id, deporte_id, jugador_id
   */
  app.get("/", { preHandler: canRead }, async (req, reply) => {
    const parsed = PageQuery.safeParse((req as any).query);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Query inválida", errors: parsed.error.flatten() });
    }

    const { limit, offset, academia_id, deporte_id, jugador_id } = parsed.data;

    const where: string[] = ["sb.partido_id IS NULL"];
    const params: any[] = [];

    if (academia_id) {
      where.push("sb.academia_id = ?");
      params.push(academia_id);
    }
    if (deporte_id) {
      where.push("sb.deporte_id = ?");
      params.push(deporte_id);
    }
    if (jugador_id) {
      where.push("sb.jugador_id = ?");
      params.push(jugador_id);
    }

    const whereSql = `WHERE ${where.join(" AND ")}`;

    // ✅ JOIN dinámico a la tabla detalle SOLO si viene deporte_id
    let sportJoinSql = "";
    let sportSelectSql = "";

    if (deporte_id && SPORT_TABLE[deporte_id]) {
      const table = SPORT_TABLE[deporte_id];
      const sportKeys = allowedSportKeys[deporte_id] ?? new Set<string>();

      // alias fijo para el detalle
      sportJoinSql = `LEFT JOIN \`${table}\` sd ON sd.stats_id = sb.id`;

      // selecciona SOLO las columnas whitelisteadas (seguro y consistente)
      const sportCols = [...sportKeys].map((k) => `sd.\`${k}\` AS \`${k}\``).join(", ");
      if (sportCols) sportSelectSql = `, ${sportCols}`;
    }

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
        ${sportSelectSql}
      FROM stats_base sb
      JOIN jugadores j ON j.id = sb.jugador_id
      ${sportJoinSql}
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
        note: deporte_id
          ? undefined
          : "Para incluir métricas de deporte (goles, asistencias, etc.) debes enviar deporte_id en la query.",
      });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al listar", error: sqlErr(err) });
    }
  });


  /**
   * ✅ GET por stats_id (cabecera + detalle)
   * /estadisticas/:id  -> id = stats_id (stats_base.id)
   *
   * OJO: esta ruta debe ir DESPUÉS de rutas específicas para no pisarlas.
   */

  /**
   * ✅ Conveniencia por jugador_id
   * GET /estadisticas/by-jugador/:jugador_id
   */
  app.get("/by-jugador/:jugador_id", { preHandler: canRead }, async (req, reply) => {
    const p = JugadorIdParam.safeParse((req as any).params);
    if (!p.success) return reply.code(400).send({ ok: false, message: "jugador_id inválido" });

    const jugador_id = Number(p.data.jugador_id);

    try {
      const joined = await getJoinedStatsByJugadorId(jugador_id);
      if (!joined) return reply.code(404).send({ ok: false, message: "Jugador no encontrado" });

      return reply.send({ ok: true, item: joined });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al obtener por jugador", error: sqlErr(err) });
    }
  });

  /**
   * ✅ Conveniencia por RUT
   * GET /estadisticas/by-rut/:rut
   */
  app.get("/by-rut/:rut", { preHandler: canRead }, async (req, reply) => {
    const parsed = RutParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: parsed.error.issues[0]?.message });

    const rut = parsed.data.rut;

    try {
      const [rows]: any = await db.query(
        "SELECT id AS jugador_id FROM jugadores WHERE rut_jugador = ? LIMIT 1",
        [rut]
      );
      const jugador_id = rows?.[0]?.jugador_id ? Number(rows[0].jugador_id) : null;
      if (!jugador_id) return reply.code(404).send({ ok: false, message: "Jugador no encontrado" });

      const joined = await getJoinedStatsByJugadorId(jugador_id);
      return reply.send({ ok: true, item: joined });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al obtener por RUT", error: sqlErr(err) });
    }
  });

  /**
   * ✅ POST /estadisticas
   * WRITE: roles 1 y 3
   * Crea/asegura stats_base + fila detalle según deporte y actualiza con payload.
   */
  app.post("/", { preHandler: canWrite }, async (req, reply) => {
    const parsed = CreateSchema.safeParse((req as any).body);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Payload inválido", errors: parsed.error.flatten() });
    }

    const body = (req as any).body || {};
    const raw = coerceNumbers(body);

    const academia_id = Number(parsed.data.academia_id);
    const deporte_id = Number(parsed.data.deporte_id);
    const jugador_id = Number(parsed.data.jugador_id);
    const partido_id = parsed.data.partido_id ?? null;

    const table = SPORT_TABLE[deporte_id];
    if (!table) return reply.code(400).send({ ok: false, message: "DEPORTE_NO_SOPORTADO" });

    // Validación dura: jugador pertenece a academia/deporte
    const scope = await getJugadorScope(jugador_id);
    if (!scope) return reply.code(404).send({ ok: false, message: "Jugador no encontrado" });

    if (scope.academia_id !== academia_id || scope.deporte_id !== deporte_id) {
      return reply.code(409).send({
        ok: false,
        message: "SCOPE_MISMATCH: jugador no coincide con academia_id/deporte_id enviados",
        scope,
        requested: { academia_id, deporte_id, jugador_id },
      });
    }

    const { base, sport, rejected } = pickBaseAndSport(deporte_id, raw);

    // nunca permitir scope en updates
    delete (base as any).academia_id;
    delete (base as any).deporte_id;
    delete (base as any).jugador_id;
    delete (base as any).partido_id;

    delete (sport as any).academia_id;
    delete (sport as any).deporte_id;
    delete (sport as any).jugador_id;
    delete (sport as any).partido_id;

    try {
      const stats_id = await ensureStatsBase(academia_id, deporte_id, jugador_id, partido_id);
      await ensureSportRow(deporte_id, stats_id);

      if (Object.keys(base).length) {
        await db.query("UPDATE stats_base SET ? WHERE id = ?", [base, stats_id]);
      }
      if (Object.keys(sport).length) {
        await db.query(`UPDATE \`${table}\` SET ? WHERE stats_id = ?`, [sport, stats_id]);
      }

      const joined = await getJoinedStatsByStatsId(stats_id);
      return reply.code(201).send({ ok: true, stats_id, item: joined, rejected_keys: rejected });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al crear/actualizar", error: sqlErr(err) });
    }
  });

  /**
   * ✅ PUT /estadisticas/:id  (id = stats_id)
   * WRITE: roles 1 y 3
   */
  app.put("/:id", { preHandler: canWrite }, async (req, reply) => {
    const pid = IdParam.safeParse((req as any).params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const stats_id = Number(pid.data.id);
    const parsedBody = UpdateSchema.safeParse((req as any).body ?? {});
    if (!parsedBody.success) {
      return reply.code(400).send({ ok: false, message: "Payload inválido", errors: parsedBody.error.flatten() });
    }

    const raw = coerceNumbers((req as any).body || {});

    try {
      const [rows]: any = await db.query("SELECT deporte_id FROM stats_base WHERE id = ? LIMIT 1", [stats_id]);
      const baseRow = rows?.[0];
      if (!baseRow) return reply.code(404).send({ ok: false, message: "No encontrado" });

      const deporte_id = Number(baseRow.deporte_id);
      const table = SPORT_TABLE[deporte_id];
      if (!table) return reply.code(400).send({ ok: false, message: "DEPORTE_NO_SOPORTADO" });

      const { base, sport, rejected } = pickBaseAndSport(deporte_id, raw);

      // impedir scope accidental
      delete (base as any).academia_id;
      delete (base as any).deporte_id;
      delete (base as any).jugador_id;
      delete (base as any).partido_id;

      delete (sport as any).academia_id;
      delete (sport as any).deporte_id;
      delete (sport as any).jugador_id;
      delete (sport as any).partido_id;

      if (!Object.keys(base).length && !Object.keys(sport).length) {
        return reply.code(400).send({
          ok: false,
          message: "No hay campos válidos para actualizar (ver rejected_keys).",
          rejected_keys: rejected,
        });
      }

      await ensureSportRow(deporte_id, stats_id);

      if (Object.keys(base).length) {
        await db.query("UPDATE stats_base SET ? WHERE id = ?", [base, stats_id]);
      }
      if (Object.keys(sport).length) {
        await db.query(`UPDATE \`${table}\` SET ? WHERE stats_id = ?`, [sport, stats_id]);
      }

      const joined = await getJoinedStatsByStatsId(stats_id);
      return reply.send({ ok: true, stats_id, item: joined, rejected_keys: rejected });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al actualizar", error: sqlErr(err) });
    }
  });

  /**
   * ✅ DELETE /estadisticas/:id (id = stats_id)
   * WRITE: roles 1 y 3
   * Borra stats_base => cascada borra detalle
   */
  app.delete("/:id", { preHandler: canWrite }, async (req, reply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const stats_id = Number(parsed.data.id);

    try {
      const [result]: any = await db.query("DELETE FROM stats_base WHERE id = ?", [stats_id]);

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, deleted: stats_id });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al eliminar", error: sqlErr(err) });
    }
  });

  /**
   * ✅ GET /estadisticas/:id  (READ)
   * lo ponemos al final para no pisar /by-rut y /by-jugador
   */
  app.get("/:id", { preHandler: canRead }, async (req, reply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const stats_id = Number(parsed.data.id);

    try {
      const joined = await getJoinedStatsByStatsId(stats_id);
      if (!joined) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, item: joined });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al obtener", error: sqlErr(err) });
    }
  });
}
