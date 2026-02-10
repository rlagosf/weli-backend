// src/routers/pagos_jugador.ts
import { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: pagos_jugador
 * Campos:
 *  id, jugador_rut, tipo_pago_id, situacion_pago_id, monto,
 *  fecha_pago (DATE/DATETIME), medio_pago_id,
 *  comprobante_url (NULL), observaciones (NULL)
 *
 * ✅ Multi-academia (WELI):
 * - pagos_jugador NO tiene academia_id directo.
 * - El scoping se hace vía jugadores.academia_id + jugadores.rut_jugador.
 * - Para rol 3 (superadmin) se exige x-academia-id como "academia objetivo".
 */

/* ────────────────────────────────────────────────────────────── */
/* Constantes de negocio                                         */
/* ────────────────────────────────────────────────────────────── */

const MENSUALIDAD_TIPO_PAGO_ID = 3; // ajusta según tu catálogo real
const DIA_CORTE_VENCIDO = 5;

/* ────────────────────────────────────────────────────────────── */
/* Helpers                                                       */
/* ────────────────────────────────────────────────────────────── */

// Normaliza fecha a YYYY-MM-DD (compatible con DATE en MySQL)
function toSQLDate(input: string): string | null {
  if (!input) return null;

  // si ya viene como YYYY-MM-DD, lo aceptamos
  if (/^\d{4}-\d{2}-\d{2}$/.test(input)) return input;

  const d = new Date(input);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10);
}

// Limpia body + alias + convierte "" → null
function normalizeBody(raw: any) {
  const norm: any = {
    jugador_rut: raw.jugador_rut ?? raw.rut,
    tipo_pago_id: raw.tipo_pago_id ?? raw.tipo_id,
    situacion_pago_id: raw.situacion_pago_id ?? raw.situacion_id,
    monto: raw.monto,
    fecha_pago: raw.fecha_pago ?? raw.fecha,
    medio_pago_id: raw.medio_pago_id ?? raw.medio_id,
    comprobante_url: raw.comprobante_url ?? raw.comprobante,
    observaciones: raw.observaciones ?? raw.obs,
  };

  if (typeof norm.comprobante_url === "string" && norm.comprobante_url.trim() === "") {
    norm.comprobante_url = null;
  }
  if (typeof norm.observaciones === "string" && norm.observaciones.trim() === "") {
    norm.observaciones = null;
  }

  return norm;
}

/**
 * Auth helpers (depende de tu middleware):
 * esperamos req.auth = { type:"user", rol_id, academia_id, ... }
 */
function getAuth(req: any) {
  return (req as any).auth as
    | { type: "user"; user_id?: number; rol_id?: number; academia_id?: number }
    | { type: "apoderado"; rut?: string }
    | undefined;
}

function getHeaderAcademiaId(req: any): number | null {
  const raw =
    (req.headers?.["x-academia-id"] as any) ??
    (req.headers?.["X-Academia-Id"] as any) ??
    null;

  const v = Array.isArray(raw) ? raw[0] : raw;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : null;
}

/**
 * ✅ Academia efectiva (anti-cruce)
 * - rol 3: requiere x-academia-id (academia "objetivo" en super-dashboard)
 * - rol 1: usa auth.academia_id; si no viene, permite fallback a header.
 */
function getAcademiaIdOr403(req: any, reply: any): number | null {
  const a = getAuth(req);
  if (!a || a.type !== "user") {
    reply.code(403).send({ ok: false, message: "FORBIDDEN" });
    return null;
  }

  const rol = Number(a.rol_id ?? 0);

  // superadmin: SIEMPRE target por header
  if (rol === 3) {
    const headerAcademia = getHeaderAcademiaId(req);
    if (!headerAcademia) {
      reply.code(403).send({ ok: false, message: "ACADEMIA_TARGET_REQUIRED" });
      return null;
    }
    return headerAcademia;
  }

  // admin/staff: academia desde token
  const tokenAcademia = Number(a.academia_id ?? 0);
  if (Number.isFinite(tokenAcademia) && tokenAcademia > 0) return tokenAcademia;

  // fallback: header
  const headerAcademia = getHeaderAcademiaId(req);
  if (headerAcademia) return headerAcademia;

  reply.code(403).send({ ok: false, message: "ACADEMIA_REQUIRED" });
  return null;
}

/**
 * ✅ Type guard para que TS entienda que academia_id ya no es null
 */
function assertAcademiaId(
  academia_id: number | null,
  reply: any
): asserts academia_id is number {
  if (!Number.isFinite(academia_id) || (academia_id as number) <= 0) {
    if (!reply.sent) reply.code(403).send({ ok: false, message: "ACADEMIA_REQUIRED" });
    throw new Error("ACADEMIA_REQUIRED");
  }
}

/**
 * Validación fuerte: el jugador pertenece a la academia efectiva
 * (sirve para POST/PUT/DELETE y evitar escritura cruzada)
 */
async function assertJugadorInAcademiaOr403(
  jugador_rut: number,
  academia_id: number,
  reply: any
) {
  const [chk]: any = await db.query(
    `SELECT rut_jugador
       FROM jugadores
      WHERE rut_jugador = ?
        AND academia_id = ?
      LIMIT 1`,
    [jugador_rut, academia_id]
  );

  if (!chk?.length) {
    reply.code(403).send({ ok: false, message: "FORBIDDEN_JUGADOR" });
    return false;
  }
  return true;
}

/* ────────────────────────────────────────────────────────────── */
/* Schemas                                                       */
/* ────────────────────────────────────────────────────────────── */

const IdParam = z.object({ id: z.coerce.number().int().positive() });
const RutParam = z.object({ jugador_rut: z.coerce.number().int().positive() });

const BaseSchema = z.object({
  jugador_rut: z.coerce.number().int().positive(),
  tipo_pago_id: z.coerce.number().int().positive(),
  situacion_pago_id: z.coerce.number().int().positive(),
  monto: z.coerce.number().nonnegative(),
  fecha_pago: z.string().min(10),
  medio_pago_id: z.coerce.number().int().positive(),
  comprobante_url: z.string().url().nullable().optional(),
  observaciones: z.string().nullable().optional(),
});

const CreateSchema = BaseSchema;
const UpdateSchema = BaseSchema.partial();

const PageQuery = z.object({
  limit: z.coerce.number().int().positive().max(1000).default(50),
  offset: z.coerce.number().int().nonnegative().default(0),
});

// 🔎 Filtros opcionales para listar
const ListQuery = PageQuery.extend({
  year: z.coerce.number().int().optional(),
  month: z.coerce.number().int().min(1).max(12).optional(),
  tipo_pago_id: z.coerce.number().int().positive().optional(),
  jugador_rut: z.coerce.number().int().positive().optional(),
});

/* ────────────────────────────────────────────────────────────── */
/* Router                                                        */
/* ────────────────────────────────────────────────────────────── */

export default async function pagos_jugador(app: FastifyInstance) {
  /**
   * 🔐 FINANZAS
   * - canRead  -> roles 1 y 3
   * - canWrite -> solo rol 1
   *
   * ✅ Aunque rol 3 lea, siempre queda scoping por academia objetivo (x-academia-id).
   */
  const canRead = [requireAuth, requireRoles([1, 3])];
  const canWrite = [requireAuth, requireRoles([1])];

  // Health
  app.get("/health", { preHandler: canRead }, async (req, reply) => {
    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;
    assertAcademiaId(academia_id, reply);

    return {
      module: "pagos_jugador",
      status: "ready",
      timestamp: new Date().toISOString(),
      academia_id,
    };
  });

  /* ───────── GET listado con filtros + paginación (SCOPED) ───────── */
  app.get("/", { preHandler: canRead }, async (req, reply) => {
    const queryParsed = ListQuery.safeParse((req as any).query);
    if (!queryParsed.success) {
      return reply.code(400).send({
        ok: false,
        message: "Query inválida",
        errors: queryParsed.error.flatten(),
      });
    }

    const { limit, offset, year, month, tipo_pago_id, jugador_rut } = queryParsed.data;

    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;
    assertAcademiaId(academia_id, reply);

    try {
      let sql = `
        SELECT p.*
          FROM pagos_jugador p
          JOIN jugadores j ON j.rut_jugador = p.jugador_rut
         WHERE j.academia_id = ?
      `;
      const params: any[] = [academia_id];

      if (jugador_rut) {
        sql += " AND p.jugador_rut = ?";
        params.push(jugador_rut);
      }

      if (tipo_pago_id) {
        sql += " AND p.tipo_pago_id = ?";
        params.push(tipo_pago_id);
      }

      if (year) {
        sql += " AND YEAR(p.fecha_pago) = ?";
        params.push(year);
      }

      if (month) {
        sql += " AND MONTH(p.fecha_pago) = ?";
        params.push(month);
      }

      sql += `
         ORDER BY p.fecha_pago DESC, p.id DESC
         LIMIT ? OFFSET ?
      `;
      params.push(limit, offset);

      const [rows] = await db.query(sql, params);

      return reply.send({
        ok: true,
        academia_id,
        items: rows,
        limit,
        offset,
        filters: { year, month, tipo_pago_id, jugador_rut },
      });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al listar pagos",
        error: err?.message,
      });
    }
  });

  /* ───────── GET estado de cuenta (SCOPED) ───────── */
  app.get("/estado-cuenta", { preHandler: canRead }, async (req, reply) => {
    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;
    assertAcademiaId(academia_id, reply);

    try {
      const now = new Date();
      const currentYear = now.getFullYear();
      const currentMonth = now.getMonth() + 1;
      const currentDay = now.getDate();

      const baseEstadoSinPago: "PAGADO" | "VENCIDO" =
        currentDay <= DIA_CORTE_VENCIDO ? "PAGADO" : "VENCIDO";

      /* 1) Jugadores + categoría (SOLO academia) */
      const [jugRows]: any = await db.query(
        `SELECT j.*,
                c.nombre AS categoria_nombre
           FROM jugadores j
           LEFT JOIN categorias c ON c.id = j.categoria_id
          WHERE j.academia_id = ?`,
        [academia_id]
      );

      /* 2) Pagos + joins a catálogos (SOLO pagos de jugadores de esa academia) */
      const [pagoRows]: any = await db.query(
        `SELECT p.*,
                tp.id     AS tp_id,
                tp.nombre AS tp_nombre,
                mp.id     AS mp_id,
                mp.nombre AS mp_nombre,
                sp.id     AS sp_id,
                sp.nombre AS sp_nombre
           FROM pagos_jugador p
           JOIN jugadores j ON j.rut_jugador = p.jugador_rut
           LEFT JOIN tipo_pago tp      ON tp.id = p.tipo_pago_id
           LEFT JOIN medio_pago mp     ON mp.id = p.medio_pago_id
           LEFT JOIN situacion_pago sp ON sp.id = p.situacion_pago_id
          WHERE j.academia_id = ?`,
        [academia_id]
      );

      const pagos = (pagoRows || []).map((r: any) => ({
        id: r.id,
        jugador_rut: r.jugador_rut,
        monto: Number(r.monto || 0),
        fecha_pago: r.fecha_pago,
        tipo_pago: { id: r.tp_id ?? r.tipo_pago_id, nombre: r.tp_nombre ?? null },
        medio_pago: { id: r.mp_id ?? r.medio_pago_id, nombre: r.mp_nombre ?? null },
        situacion_pago: { id: r.sp_id ?? r.situacion_pago_id, nombre: r.sp_nombre ?? null },
        comprobante_url: r.comprobante_url ?? null,
        observaciones: r.observaciones ?? null,
      }));

      type PagoEnvuelto = { pago: any; year: number | null; month: number | null };
      const pagosPorRut = new Map<string, PagoEnvuelto[]>();

      for (const p of pagos) {
        const rut = String(p.jugador_rut ?? "");
        if (!rut) continue;

        const d = p.fecha_pago ? new Date(p.fecha_pago) : null;
        const year = d && !Number.isNaN(d.getTime()) ? d.getFullYear() : null;
        const month = d && !Number.isNaN(d.getTime()) ? d.getMonth() + 1 : null;

        const arr = pagosPorRut.get(rut) || [];
        arr.push({ pago: p, year, month });
        pagosPorRut.set(rut, arr);
      }

      const filas = (jugRows || []).map((j: any) => {
        const rut = String(j.rut_jugador ?? j.rut ?? "");
        const nombre = j.nombre_jugador ?? j.nombre ?? j.nombre_completo ?? "—";
        const categoria = j.categoria_nombre ?? j.categoria ?? "Sin categoría";

        const arrAll = rut ? pagosPorRut.get(rut) || [] : [];

        const arrMensual = arrAll.filter(
          (x) => Number(x.pago?.tipo_pago?.id) === MENSUALIDAD_TIPO_PAGO_ID
        );

        const pagosMensualMesActual = arrMensual.filter(
          (x) => x.year === currentYear && x.month === currentMonth
        );

        let estadoMensualidad: "PAGADO" | "VENCIDO" = baseEstadoSinPago;
        if (pagosMensualMesActual.length > 0) estadoMensualidad = "PAGADO";

        let lastPago: any = null;
        if (arrAll.length > 0) {
          arrAll.sort((a, b) => {
            const da = a.pago.fecha_pago ? new Date(a.pago.fecha_pago).getTime() : 0;
            const dbt = b.pago.fecha_pago ? new Date(b.pago.fecha_pago).getTime() : 0;
            return dbt - da;
          });
          lastPago = arrAll[0].pago;
        }

        return { rut, nombre, categoria, estadoMensualidad, lastPago };
      });

      const mesLabel = new Intl.DateTimeFormat("es-CL", {
        month: "long",
        year: "numeric",
      }).format(now);

      return reply.send({
        ok: true,
        academia_id,
        filas,
        pagos,
        mes: {
          year: currentYear,
          month: currentMonth,
          dia_corte: DIA_CORTE_VENCIDO,
          label: mesLabel,
        },
      });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al calcular estado de cuenta",
        error: err?.message,
      });
    }
  });

  /* ───────── GET estado mensualidad (solo deudores) (SCOPED) ───────── */
  app.get("/mensualidad-estado", { preHandler: canRead }, async (req, reply) => {
    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;
    assertAcademiaId(academia_id, reply);

    try {
      const now = new Date();
      const currentYear = now.getFullYear();
      const currentMonth = now.getMonth() + 1;
      const currentDay = now.getDate();

      const [jugRows]: any = await db.query(
        `SELECT j.*,
                c.nombre AS categoria_nombre
           FROM jugadores j
           LEFT JOIN categorias c ON c.id = j.categoria_id
          WHERE j.academia_id = ?`,
        [academia_id]
      );

      const [mensRows]: any = await db.query(
        `SELECT p.jugador_rut,
                MAX(p.fecha_pago) AS last_fecha
           FROM pagos_jugador p
           JOIN jugadores j ON j.rut_jugador = p.jugador_rut
          WHERE p.tipo_pago_id = ?
            AND j.academia_id = ?
          GROUP BY p.jugador_rut`,
        [MENSUALIDAD_TIPO_PAGO_ID, academia_id]
      );

      const lastMensPorRut = new Map<string, string | null>();
      for (const r of mensRows || []) {
        if (!r.jugador_rut) continue;

        let fechaStr: string | null = null;
        if (r.last_fecha instanceof Date) fechaStr = r.last_fecha.toISOString().slice(0, 10);
        else if (typeof r.last_fecha === "string") fechaStr = r.last_fecha.slice(0, 10);

        lastMensPorRut.set(String(r.jugador_rut), fechaStr);
      }

      const filas: any[] = [];

      for (const j of jugRows || []) {
        const rut = String(j.rut_jugador ?? j.rut ?? "");
        const nombre = j.nombre_jugador ?? j.nombre ?? j.nombre_completo ?? "—";
        const categoria = j.categoria_nombre ?? j.categoria ?? "Sin categoría";

        const lastFechaRaw = rut ? lastMensPorRut.get(rut) ?? null : null;

        let lastMensualidadFecha: string | null = null;
        let tieneMensualidadMesActual = false;

        if (lastFechaRaw) {
          const s = String(lastFechaRaw).slice(0, 10);
          const [yStr, mStr] = s.split("-");
          const y = Number(yStr);
          const m = Number(mStr);

          if (!Number.isNaN(y) && !Number.isNaN(m)) {
            lastMensualidadFecha = s;
            if (y === currentYear && m === currentMonth) {
              tieneMensualidadMesActual = true;
            }
          }
        }

        let estadoMensualidad: "PAGADO" | "VENCIDO";
        if (currentDay <= DIA_CORTE_VENCIDO) estadoMensualidad = "PAGADO";
        else estadoMensualidad = tieneMensualidadMesActual ? "PAGADO" : "VENCIDO";

        if (estadoMensualidad !== "VENCIDO") continue;

        filas.push({
          rut,
          nombre,
          categoria,
          estadoMensualidad,
          lastMensualidadFecha,
          tieneMensualidadMesActual,
        });
      }

      const mesLabel = new Intl.DateTimeFormat("es-CL", {
        month: "long",
        year: "numeric",
      }).format(now);

      return reply.send({
        ok: true,
        academia_id,
        mes: {
          year: currentYear,
          month: currentMonth,
          dia_corte: DIA_CORTE_VENCIDO,
          label: mesLabel,
        },
        filas,
      });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al calcular estado de mensualidad",
        error: err?.message,
      });
    }
  });

  /* ───────── GET por jugador_rut (SCOPED) ───────── */
  // ✅ Importante: va ANTES de "/:id" para no ser capturado por la ruta dinámica.
  app.get("/jugador/:jugador_rut", { preHandler: canRead }, async (req, reply) => {
    const parsed = RutParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "RUT inválido" });

    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;
    assertAcademiaId(academia_id, reply);

    try {
      const [rows] = await db.query(
        `
        SELECT p.*
          FROM pagos_jugador p
          JOIN jugadores j ON j.rut_jugador = p.jugador_rut
         WHERE p.jugador_rut = ?
           AND j.academia_id = ?
         ORDER BY p.fecha_pago DESC, p.id DESC
        `,
        [parsed.data.jugador_rut, academia_id]
      );

      return reply.send({ ok: true, academia_id, items: rows });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al listar pagos por jugador",
        error: err?.message,
      });
    }
  });

  /* ───────── GET por ID (SCOPED) ───────── */
  app.get("/:id", { preHandler: canRead }, async (req, reply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;
    assertAcademiaId(academia_id, reply);

    try {
      const [rows]: any = await db.query(
        `
        SELECT p.*
          FROM pagos_jugador p
          JOIN jugadores j ON j.rut_jugador = p.jugador_rut
         WHERE p.id = ?
           AND j.academia_id = ?
         LIMIT 1
        `,
        [parsed.data.id, academia_id]
      );

      if (!rows?.length) return reply.code(404).send({ ok: false, message: "Pago no encontrado" });

      return reply.send({ ok: true, academia_id, item: rows[0] });
    } catch (err: any) {
      return reply.code(500).send({
        ok: false,
        message: "Error al obtener pago",
        error: err?.message,
      });
    }
  });

  /* ───────── POST crear (SCOPED + valida jugador) ───────── */
  app.post("/", { preHandler: canWrite }, async (req, reply) => {
    const raw = (req as any).body ?? {};
    const normalized = normalizeBody(raw);

    const parsed = CreateSchema.safeParse(normalized);
    if (!parsed.success) {
      return reply.code(400).send({
        ok: false,
        message: "Payload inválido",
        errors: parsed.error.flatten(),
      });
    }

    const data = parsed.data;

    const sqlDate = toSQLDate(data.fecha_pago);
    if (!sqlDate) return reply.code(400).send({ ok: false, message: "fecha_pago inválida" });
    data.fecha_pago = sqlDate;

    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;
    assertAcademiaId(academia_id, reply);

    const ok = await assertJugadorInAcademiaOr403(data.jugador_rut, academia_id, reply);
    if (!ok) return;

    try {
      const [result]: any = await db.query("INSERT INTO pagos_jugador SET ?", [data]);
      return reply.code(201).send({ ok: true, academia_id, id: result.insertId, ...data });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al crear pago", error: err?.message });
    }
  });

  /* ───────── PUT actualizar (SCOPED + valida jugador) ───────── */
  app.put("/:id", { preHandler: canWrite }, async (req, reply) => {
    const pid = IdParam.safeParse((req as any).params);
    if (!pid.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const id = pid.data.id;

    const raw = (req as any).body ?? {};
    const normalized = normalizeBody(raw);

    const parsed = UpdateSchema.safeParse(normalized);
    if (!parsed.success) {
      return reply.code(400).send({
        ok: false,
        message: "Payload inválido",
        errors: parsed.error.flatten(),
      });
    }

    const data = parsed.data;

    if (data.fecha_pago) {
      const sqlDate = toSQLDate(data.fecha_pago);
      if (!sqlDate) return reply.code(400).send({ ok: false, message: "fecha_pago inválida" });
      data.fecha_pago = sqlDate;
    }

    if (Object.keys(data).length === 0) {
      return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
    }

    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;
    assertAcademiaId(academia_id, reply);

    const [exists]: any = await db.query(
      `
      SELECT p.id, p.jugador_rut
        FROM pagos_jugador p
        JOIN jugadores j ON j.rut_jugador = p.jugador_rut
       WHERE p.id = ?
         AND j.academia_id = ?
       LIMIT 1
      `,
      [id, academia_id]
    );
    if (!exists?.length) return reply.code(404).send({ ok: false, message: "Pago no encontrado" });

    if (data.jugador_rut) {
      const ok = await assertJugadorInAcademiaOr403(data.jugador_rut, academia_id, reply);
      if (!ok) return;
    }

    try {
      const [result]: any = await db.query("UPDATE pagos_jugador SET ? WHERE id = ?", [data, id]);

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "Pago no encontrado" });

      return reply.send({ ok: true, academia_id, updated: { id, ...data } });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al actualizar pago", error: err?.message });
    }
  });

  /* ───────── DELETE eliminar (SCOPED) ───────── */
  app.delete("/:id", { preHandler: canWrite }, async (req, reply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) return reply.code(400).send({ ok: false, message: "ID inválido" });

    const academia_id = getAcademiaIdOr403(req, reply);
    if ((reply as any).sent) return;
    assertAcademiaId(academia_id, reply);

    try {
      const [result]: any = await db.query(
        `
        DELETE p
          FROM pagos_jugador p
          JOIN jugadores j ON j.rut_jugador = p.jugador_rut
         WHERE p.id = ?
           AND j.academia_id = ?
        `,
        [parsed.data.id, academia_id]
      );

      if (result.affectedRows === 0) return reply.code(404).send({ ok: false, message: "Pago no encontrado" });

      return reply.send({ ok: true, academia_id, deleted: parsed.data.id });
    } catch (err: any) {
      return reply.code(500).send({ ok: false, message: "Error al eliminar pago", error: err?.message });
    }
  });
}
