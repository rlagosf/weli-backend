// src/routers/pagos_jugador.ts
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
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
 * - Scoping SIEMPRE vía JOIN jugadores (j.academia_id).
 * - Regla platino: todo vive en la academia efectiva.
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

/* ──────────────────────────────────────────────────────────────
   Multi-academia helpers (WELI) — MISMO ESTÁNDAR que jugadores.ts
   Regla final:
   - Rol 3 (superadmin): x-academia-id obligatorio y define el tenant.
   - Rol 1/2 (admin/staff): pueden enviar x-academia-id, pero SOLO si coincide con el token.
   - Si no viene header: usa academia_id del token.
────────────────────────────────────────────────────────────── */

type AuthLike = {
  rol_id?: number;
  role_id?: number;
  role?: number;

  academia_id?: number;
  academy_id?: number;
  academiaId?: number;
  academyId?: number;
  academia?: number;
  academy?: number;
};

function getAuthLike(req: FastifyRequest): AuthLike {
  const a: any = (req as any).auth;
  const u: any = (req as any).user;
  const ctx =
    a && typeof a === "object"
      ? a
      : u && typeof u === "object"
      ? u
      : {};
  return ctx as AuthLike;
}

function getRolId(req: FastifyRequest): number {
  const ctx = getAuthLike(req);
  const raw = ctx.rol_id ?? ctx.role_id ?? ctx.role ?? 0;
  const n = Number(raw);
  return Number.isFinite(n) ? n : 0;
}

function getTokenAcademiaId(req: FastifyRequest): number {
  const ctx = getAuthLike(req);
  const raw =
    ctx.academia_id ??
    ctx.academy_id ??
    ctx.academiaId ??
    ctx.academyId ??
    ctx.academia ??
    ctx.academy ??
    0;

  const n = Number(raw);
  return Number.isFinite(n) ? n : 0;
}

function getHeaderAcademiaId(req: FastifyRequest): number {
  const hdr = req.headers["x-academia-id"];
  const raw = Array.isArray(hdr) ? hdr[0] : hdr;
  const n = Number(raw);
  return Number.isFinite(n) ? n : 0;
}

function getEffectiveAcademiaId(req: FastifyRequest): number {
  const rol = getRolId(req);
  const headerAcademia = getHeaderAcademiaId(req);
  const tokenAcademia = getTokenAcademiaId(req);

  // 1) Superadmin: header manda (obligatorio)
  if (rol === 3) {
    if (!headerAcademia || headerAcademia <= 0) {
      throw Object.assign(new Error("FORBIDDEN: falta x-academia-id para superadmin"), {
        statusCode: 403,
      });
    }
    return headerAcademia;
  }

  // 2) Admin/Staff: si viene header, debe coincidir con token
  if (headerAcademia && headerAcademia > 0) {
    if (!tokenAcademia || tokenAcademia <= 0) {
      throw Object.assign(new Error("FORBIDDEN: token sin academia_id"), { statusCode: 403 });
    }
    if (headerAcademia !== tokenAcademia) {
      throw Object.assign(new Error("FORBIDDEN: x-academia-id no coincide con tu academia"), {
        statusCode: 403,
      });
    }
    return headerAcademia;
  }

  // 3) Fallback: token
  if (!tokenAcademia || tokenAcademia <= 0) {
    throw Object.assign(new Error("FORBIDDEN: token sin academia_id"), { statusCode: 403 });
  }
  return tokenAcademia;
}

/**
 * Validación fuerte: el jugador pertenece a la academia efectiva
 * (sirve para POST/PUT/DELETE y evitar escritura cruzada)
 */
async function assertJugadorInAcademiaOrThrow(jugador_rut: number, academia_id: number) {
  const [chk]: any = await db.query(
    `SELECT rut_jugador
       FROM jugadores
      WHERE rut_jugador = ?
        AND academia_id = ?
      LIMIT 1`,
    [jugador_rut, academia_id]
  );

  if (!chk?.length) {
    throw Object.assign(new Error("FORBIDDEN_JUGADOR"), { statusCode: 403 });
  }
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
   * - canWrite -> roles 1 y 3 (según tu requerimiento actual)
   *
   * ✅ Todo scoped por academia efectiva (JOIN jugadores).
   */
  const canRead = [requireAuth, requireRoles([1, 3])];
  const canWrite = [requireAuth, requireRoles([1, 3])];

  // Health
  app.get("/health", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academia_id = getEffectiveAcademiaId(req);
      reply.header("Cache-Control", "no-store");
      return {
        module: "pagos_jugador",
        status: "ready",
        timestamp: new Date().toISOString(),
        academia_id,
      };
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error /health pagos_jugador", detail: err?.message });
    }
  });

  /* ───────── GET listado con filtros + paginación (SCOPED) ───────── */
  app.get("/", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const queryParsed = ListQuery.safeParse((req as any).query);
    if (!queryParsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "Query inválida", errors: queryParsed.error.flatten() });
    }

    const { limit, offset, year, month, tipo_pago_id, jugador_rut } = queryParsed.data;

    try {
      const academia_id = getEffectiveAcademiaId(req);

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

      reply.header("Cache-Control", "no-store");
      return reply.send({ ok: true, academia_id, items: rows, limit, offset, filters: { year, month, tipo_pago_id, jugador_rut } });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al listar pagos", detail: err?.message });
    }
  });

  /* ───────── GET estado de cuenta (SCOPED) ───────── */
  app.get("/estado-cuenta", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academia_id = getEffectiveAcademiaId(req);

      const now = new Date();
      const currentYear = now.getFullYear();
      const currentMonth = now.getMonth() + 1;
      const currentDay = now.getDate();

      const baseEstadoSinPago: "PAGADO" | "VENCIDO" = currentDay <= DIA_CORTE_VENCIDO ? "PAGADO" : "VENCIDO";

      const [jugRows]: any = await db.query(
        `SELECT j.*,
                c.nombre AS categoria_nombre
           FROM jugadores j
           LEFT JOIN categorias c ON c.id = j.categoria_id
          WHERE j.academia_id = ?`,
        [academia_id]
      );

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
        const arrMensual = arrAll.filter((x) => Number(x.pago?.tipo_pago?.id) === MENSUALIDAD_TIPO_PAGO_ID);

        const pagosMensualMesActual = arrMensual.filter((x) => x.year === currentYear && x.month === currentMonth);

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

      const mesLabel = new Intl.DateTimeFormat("es-CL", { month: "long", year: "numeric" }).format(now);

      reply.header("Cache-Control", "no-store");
      return reply.send({
        ok: true,
        academia_id,
        filas,
        pagos,
        mes: { year: currentYear, month: currentMonth, dia_corte: DIA_CORTE_VENCIDO, label: mesLabel },
      });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al calcular estado de cuenta", detail: err?.message });
    }
  });

  /* ───────── GET estado mensualidad (solo deudores) (SCOPED) ───────── */
  app.get("/mensualidad-estado", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      const academia_id = getEffectiveAcademiaId(req);

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
            if (y === currentYear && m === currentMonth) tieneMensualidadMesActual = true;
          }
        }

        let estadoMensualidad: "PAGADO" | "VENCIDO";
        if (currentDay <= DIA_CORTE_VENCIDO) estadoMensualidad = "PAGADO";
        else estadoMensualidad = tieneMensualidadMesActual ? "PAGADO" : "VENCIDO";

        if (estadoMensualidad !== "VENCIDO") continue;

        filas.push({ rut, nombre, categoria, estadoMensualidad, lastMensualidadFecha, tieneMensualidadMesActual });
      }

      const mesLabel = new Intl.DateTimeFormat("es-CL", { month: "long", year: "numeric" }).format(now);

      reply.header("Cache-Control", "no-store");
      return reply.send({
        ok: true,
        academia_id,
        mes: { year: currentYear, month: currentMonth, dia_corte: DIA_CORTE_VENCIDO, label: mesLabel },
        filas,
      });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al calcular estado de mensualidad", detail: err?.message });
    }
  });

  /* ───────── GET por jugador_rut (SCOPED) ───────── */
  app.get("/jugador/:jugador_rut", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = RutParam.safeParse((req as any).params);
    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "RUT inválido" });
    }

    try {
      const academia_id = getEffectiveAcademiaId(req);

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

      reply.header("Cache-Control", "no-store");
      return reply.send({ ok: true, academia_id, items: rows });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al listar pagos por jugador", detail: err?.message });
    }
  });

  /* ───────── GET por ID (SCOPED) ───────── */
  app.get("/:id", { preHandler: canRead }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const academia_id = getEffectiveAcademiaId(req);

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

      reply.header("Cache-Control", "no-store");
      if (!rows?.length) return reply.code(404).send({ ok: false, message: "Pago no encontrado" });

      return reply.send({ ok: true, academia_id, item: rows[0] });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al obtener pago", detail: err?.message });
    }
  });

  /* ───────── POST crear (SCOPED + valida jugador) ───────── */
  app.post("/", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const raw = (req as any).body ?? {};
    const normalized = normalizeBody(raw);

    const parsed = CreateSchema.safeParse(normalized);
    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "Payload inválido", errors: parsed.error.flatten() });
    }

    const data = parsed.data;

    const sqlDate = toSQLDate(String(data.fecha_pago));
    if (!sqlDate) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "fecha_pago inválida" });
    }
    data.fecha_pago = sqlDate;

    try {
      const academia_id = getEffectiveAcademiaId(req);

      await assertJugadorInAcademiaOrThrow(data.jugador_rut, academia_id);

      const [result]: any = await db.query("INSERT INTO pagos_jugador SET ?", [data]);

      reply.header("Cache-Control", "no-store");
      return reply.code(201).send({ ok: true, academia_id, id: result.insertId, item: { id: result.insertId, ...data } });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      const msg = err?.message === "FORBIDDEN_JUGADOR" ? "FORBIDDEN_JUGADOR" : "Error al crear pago";
      return reply.code(code).send({ ok: false, message: msg, detail: err?.message });
    }
  });

  /* ───────── PUT actualizar (SCOPED + valida jugador) ───────── */
  app.put("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const pid = IdParam.safeParse((req as any).params);
    if (!pid.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }
    const id = pid.data.id;

    const raw = (req as any).body ?? {};
    const normalized = normalizeBody(raw);

    const parsed = UpdateSchema.safeParse(normalized);
    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "Payload inválido", errors: parsed.error.flatten() });
    }

    const data = parsed.data;

    if (data.fecha_pago) {
      const sqlDate = toSQLDate(String(data.fecha_pago));
      if (!sqlDate) {
        reply.header("Cache-Control", "no-store");
        return reply.code(400).send({ ok: false, message: "fecha_pago inválida" });
      }
      data.fecha_pago = sqlDate;
    }

    if (Object.keys(data).length === 0) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "No hay campos para actualizar" });
    }

    try {
      const academia_id = getEffectiveAcademiaId(req);

      // Asegura que el pago a editar pertenece a la academia efectiva
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
      if (!exists?.length) {
        reply.header("Cache-Control", "no-store");
        return reply.code(404).send({ ok: false, message: "Pago no encontrado" });
      }

      // Si quieren mover el pago a otro jugador: valida pertenencia
      if (data.jugador_rut) {
        await assertJugadorInAcademiaOrThrow(Number(data.jugador_rut), academia_id);
      }

      const [result]: any = await db.query("UPDATE pagos_jugador SET ? WHERE id = ?", [data, id]);

      reply.header("Cache-Control", "no-store");
      if (!result?.affectedRows) return reply.code(404).send({ ok: false, message: "Pago no encontrado" });

      return reply.send({ ok: true, academia_id, updated: { id, ...data } });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      const msg = err?.message === "FORBIDDEN_JUGADOR" ? "FORBIDDEN_JUGADOR" : "Error al actualizar pago";
      return reply.code(code).send({ ok: false, message: msg, detail: err?.message });
    }
  });

  /* ───────── DELETE eliminar (SCOPED) ───────── */
  app.delete("/:id", { preHandler: canWrite }, async (req: FastifyRequest, reply: FastifyReply) => {
    const parsed = IdParam.safeParse((req as any).params);
    if (!parsed.success) {
      reply.header("Cache-Control", "no-store");
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const academia_id = getEffectiveAcademiaId(req);

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

      reply.header("Cache-Control", "no-store");
      if (!result?.affectedRows) return reply.code(404).send({ ok: false, message: "Pago no encontrado" });

      return reply.send({ ok: true, academia_id, deleted: parsed.data.id });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({ ok: false, message: "Error al eliminar pago", detail: err?.message });
    }
  });
}
