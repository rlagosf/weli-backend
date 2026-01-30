// src/routes/estadisticas.ts
import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { z } from "zod";
import { db } from "../db";
import { requireAuth } from "../middlewares/authz";

// ─────────────────── Schemas ───────────────────
const IdParam = z.object({ id: z.string().regex(/^\d+$/, "ID inválido") });
const EstadisticaIdParam = z.object({ estadistica_id: z.string().regex(/^\d+$/, "estadistica_id inválido") });
const RutParam = z.object({ rut: z.string().regex(/^\d{7,8}$/, "RUT inválido (7 u 8 dígitos sin DV)") });

const PageQuery = z.object({
  limit: z.coerce.number().int().positive().max(200).optional().default(50),
  offset: z.coerce.number().int().nonnegative().optional().default(0),
});

// Whitelist de campos permitidos
const allowedKeys = new Set([
  "estadistica_id",
  "goles",
  "asistencias",
  "tiros_libres",
  "penales",
  "lesiones",
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
  "minutos_jugados",
  "partidos_jugador",
  "dias_baja",
  "sanciones_federativas",
  "torneos_convocados",
  "titular_partidos",
]);

const CreateSchema = z
  .object({
    estadistica_id: z.coerce.number().int().positive(),
  })
  .passthrough();

// Helpers
const sqlErr = (err: any) => err?.sqlMessage || err?.message || "DB error";

// 🔐 Guard robusto (acepta rol 1 y 2 aunque venga como string o con otra key)
function getRoleFromReq(req: any): number | null {
  const u = req?.user ?? req?.auth?.user ?? req?.session?.user ?? null;
  if (!u) return null;

  const raw =
    u.rol_id ??
    u.role_id ??
    u.roleId ??
    u.rol ??
    u.role ??
    u.rolId ??
    null;

  if (raw === null || raw === undefined) return null;

  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}

function requireRolesLoose(allowed: number[]) {
  const set = new Set(allowed.map((x) => Number(x)));
  return async (req: FastifyRequest, reply: FastifyReply) => {
    const role = getRoleFromReq(req as any);

    if (role == null || !set.has(role)) {
      (req as any).log?.warn?.(
        { role, user: (req as any).user },
        "[estadisticas] access denied (role mismatch)"
      );
      return reply.code(403).send({ ok: false, message: "FORBIDDEN" });
    }
  };
}

// Normaliza tipos numéricos
function coerceNumbers(obj: Record<string, any>) {
  const out: Record<string, any> = { ...obj };

  for (const [k, v] of Object.entries(out)) {
    if (v === null || v === undefined || v === "") continue;
    if (!allowedKeys.has(k)) continue;

    if (k === "distancia_recorrida_km") {
      const n = Number.parseFloat(String(v));
      out[k] = Number.isFinite(n) ? n : 0;
    } else {
      const n = Number.parseInt(String(v), 10);
      out[k] = Number.isFinite(n) ? n : 0;
    }
  }
  return out;
}

export default async function estadisticas(app: FastifyInstance) {
  // ✅ FULL ACCESS: roles 1 y 2 (leer + crear + editar + eliminar)
  const canAccess = [requireAuth, requireRolesLoose([1, 2])];

  // ─────────────────── Descubrir columnas reales ───────────────────
  let dbColumns = new Set<string>();

  async function refreshDbColumns() {
    try {
      const [rows]: any = await db.query("SHOW COLUMNS FROM estadisticas");
      dbColumns = new Set((rows || []).map((r: any) => r.Field));
      app.log.info({ columns: Array.from(dbColumns) }, "estadisticas: columnas detectadas");
    } catch (e) {
      app.log.error({ err: e }, 'No se pudieron leer columnas de "estadisticas"');
      dbColumns = new Set(); // fallback: no filtramos por columnas reales
    }
  }

  await refreshDbColumns();

  function filterToDbColumns(obj: Record<string, any>) {
    const accepted: Record<string, any> = {};
    const rejected: string[] = [];

    for (const [k, v] of Object.entries(obj)) {
      const existsInDb = dbColumns.size === 0 || dbColumns.has(k);
      if (allowedKeys.has(k) && existsInDb) accepted[k] = v;
      else rejected.push(k);
    }
    return { accepted, rejected };
  }

  // Health (roles 1/2)
  app.get("/health", { preHandler: canAccess }, async () => ({
    module: "estadisticas",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // Debug auth (roles 1/2) — para cazar qué trae req.user sin abrirlo al mundo
  app.get("/debug/whoami", { preHandler: canAccess }, async (req: any, reply) => {
    return reply.send({
      ok: true,
      roleDetected: getRoleFromReq(req),
      user: req.user ?? null,
    });
  });

  // Debug columnas (roles 1/2)
  app.get("/debug/columns", { preHandler: canAccess }, async (_req, reply) => {
    return reply.send({ ok: true, columns: Array.from(dbColumns) });
  });

  // ─────────────────── Listado paginado (roles 1/2) ───────────────────
  app.get("/", { preHandler: canAccess }, async (req, reply) => {
    const parsed = PageQuery.safeParse((req as any).query);
    const { limit, offset } = parsed.success ? parsed.data : { limit: 50, offset: 0 };

    try {
      const [rows] = await db.query("SELECT * FROM estadisticas ORDER BY id DESC LIMIT ? OFFSET ?", [
        limit,
        offset,
      ]);
      return reply.send({ ok: true, items: rows, limit, offset });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al listar", error: sqlErr(err) });
    }
  });

  // ─────────────────── Obtener por estadistica_id (roles 1/2) ───────────────────
  app.get("/estadistica/:estadistica_id", { preHandler: canAccess }, async (req, reply) => {
    const parsed = EstadisticaIdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "estadistica_id inválido" });

    const estadistica_id = Number(parsed.data.estadistica_id);

    try {
      const [rows]: any = await db.query(
        "SELECT * FROM estadisticas WHERE estadistica_id = ? ORDER BY id DESC",
        [estadistica_id]
      );
      return reply.send({ ok: true, items: rows });
    } catch (err: any) {
      return reply
        .code(500)
        .send({ ok: false, message: "Error al listar por estadistica_id", error: sqlErr(err) });
    }
  });

  // ─────────────────── Conveniencia por RUT (roles 1/2) ───────────────────
  app.get("/by-rut/:rut", { preHandler: canAccess }, async (req, reply) => {
    const parsed = RutParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: parsed.error.issues[0]?.message });

    const rut = parsed.data.rut;

    try {
      const [rows]: any = await db.query(
        `SELECT e.*
           FROM jugadores j
           JOIN estadisticas e ON e.estadistica_id = j.estadistica_id
          WHERE j.rut_jugador = ?
          ORDER BY e.id DESC`,
        [rut]
      );
      return reply.send({ ok: true, items: rows });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al listar por RUT", error: sqlErr(err) });
    }
  });

  // ─────────────────── Crear (roles 1/2) ───────────────────
  app.post("/", { preHandler: canAccess }, async (req, reply) => {
    const parsed = CreateSchema.safeParse((req as any).body);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, message: "Payload inválido", errors: parsed.error.flatten() });
    }

    const raw = coerceNumbers(((req as any).body || {}) as Record<string, any>);
    const { accepted, rejected } = filterToDbColumns(raw);

    if (accepted.estadistica_id == null) {
      return reply.code(400).send({ ok: false, message: "estadistica_id es requerido" });
    }

    try {
      const [result]: any = await db.query("INSERT INTO estadisticas SET ?", [accepted]);
      return reply.code(201).send({ ok: true, id: result.insertId, ...accepted, rejected_keys: rejected });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al crear", error: sqlErr(err), rejected_keys: rejected });
    }
  });

  // ─────────────────── Actualizar por estadistica_id (roles 1/2) ───────────────────
  app.put("/estadistica/:estadistica_id", { preHandler: canAccess }, async (req, reply) => {
    const p = EstadisticaIdParam.safeParse((req as any).params);
    if (!p.success) return reply.code(400).send({ ok: false, message: "estadistica_id inválido" });

    const estadistica_id = Number(p.data.estadistica_id);

    const raw = coerceNumbers(((req as any).body || {}) as Record<string, any>);
    const { accepted, rejected } = filterToDbColumns(raw);
    delete accepted.estadistica_id;

    if (Object.keys(accepted).length === 0) {
      return reply.code(400).send({
        ok: false,
        message: "No hay campos válidos para actualizar (ver rejected_keys).",
        rejected_keys: rejected,
      });
    }

    try {
      const [result]: any = await db.query("UPDATE estadisticas SET ? WHERE estadistica_id = ?", [
        accepted,
        estadistica_id,
      ]);

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, updated: { estadistica_id, ...accepted }, rejected_keys: rejected });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar",
        error: sqlErr(err),
        rejected_keys: rejected,
      });
    }
  });

  // ─────────────────── Actualizar por id (PK) (roles 1/2) ───────────────────
  app.put("/:id", { preHandler: canAccess }, async (req, reply) => {
    const pid = IdParam.safeParse((req as any).params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = Number(pid.data.id);

    const raw = coerceNumbers(((req as any).body || {}) as Record<string, any>);
    const { accepted, rejected } = filterToDbColumns(raw);

    if (Object.keys(accepted).length === 0) {
      return reply.code(400).send({
        ok: false,
        message: "No hay campos válidos para actualizar (ver rejected_keys).",
        rejected_keys: rejected,
      });
    }

    try {
      const [result]: any = await db.query("UPDATE estadisticas SET ? WHERE id = ?", [accepted, id]);

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, updated: { id, ...accepted }, rejected_keys: rejected });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al actualizar",
        error: sqlErr(err),
        rejected_keys: rejected,
      });
    }
  });

  // ─────────────────── Obtener por id (PK) (roles 1/2) ───────────────────
  // ✅ Al final para no pisar rutas específicas
  app.get("/:id", { preHandler: canAccess }, async (req, reply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = Number(parsed.data.id);

    try {
      const [rows]: any = await db.query("SELECT * FROM estadisticas WHERE id = ? LIMIT 1", [id]);

      if (!rows || rows.length === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, item: rows[0] });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al obtener", error: sqlErr(err) });
    }
  });

  // ─────────────────── Eliminar por id (roles 1/2) ───────────────────
  app.delete("/:id", { preHandler: canAccess }, async (req, reply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = Number(parsed.data.id);

    try {
      const [result]: any = await db.query("DELETE FROM estadisticas WHERE id = ?", [id]);

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "No encontrado" });

      return reply.send({ ok: true, deleted: id });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al eliminar", error: sqlErr(err) });
    }
  });
}
