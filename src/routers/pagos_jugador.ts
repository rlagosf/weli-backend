// src/routers/pagos_jugador.ts
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

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
 * - tipo_pago es catálogo global.
 * - el tipo_pago_id utilizado debe estar habilitado para la academia
 *   mediante academia_tipo_pago.
 * - situacion_pago se utiliza como catálogo de estado de la transacción.
 */

/* ────────────────────────────────────────────────────────────── */
/* Constantes de negocio                                         */
/* ────────────────────────────────────────────────────────────── */

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

function resolveAcademiaId(req: FastifyRequest) {
  const academiaId = Number(getEffectiveAcademiaId(req));

  if (!Number.isInteger(academiaId) || academiaId <= 0) {
    const err: any = new Error("Academia efectiva inválida");
    err.statusCode = 403;
    throw err;
  }

  return academiaId;
}

async function assertTipoPagoEnabledOrThrow(tipoPagoId: number, academiaId: number) {
  const [rows]: any = await db.query(
    `
      SELECT tp.id
      FROM tipo_pago tp
      INNER JOIN academia_tipo_pago atp
        ON atp.tipo_pago_id = tp.id
       AND atp.academia_id = ?
       AND atp.estado_id = 1
      WHERE tp.id = ?
      LIMIT 1
    `,
    [academiaId, tipoPagoId]
  );

  if (!rows?.length) {
    throw Object.assign(
      new Error("El tipo de pago no existe o no está habilitado para la academia"),
      { statusCode: 400 }
    );
  }
}

async function assertSituacionPagoExistsOrThrow(situacionPagoId: number, academiaId: number) {
  const [rows]: any = await db.query(
    `
      SELECT id
      FROM situacion_pago
      WHERE id = ?
        AND (
          academia_id IS NULL
          OR academia_id = ?
        )
      LIMIT 1
    `,
    [situacionPagoId, academiaId]
  );

  if (!rows?.length) {
    throw Object.assign(
      new Error("La situación de pago no existe o no corresponde a la academia"),
      { statusCode: 400 }
    );
  }
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
      const academia_id = resolveAcademiaId(req);
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
      const academia_id = resolveAcademiaId(req);

      let sql = `
        SELECT
          p.*,
          tp.nombre AS tipo_pago_nombre,
          sp.nombre AS situacion_pago_nombre,
          mp.nombre AS medio_pago_nombre
        FROM pagos_jugador p
        JOIN jugadores j
          ON j.rut_jugador = p.jugador_rut
        LEFT JOIN tipo_pago tp
          ON tp.id = p.tipo_pago_id
        LEFT JOIN academia_tipo_pago atp
          ON atp.academia_id = j.academia_id
         AND atp.tipo_pago_id = p.tipo_pago_id
        LEFT JOIN situacion_pago sp
          ON sp.id = p.situacion_pago_id
        LEFT JOIN medio_pago mp
          ON mp.id = p.medio_pago_id
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
      const academia_id = resolveAcademiaId(req);

      const [rows]: any = await db.query(
        `
          SELECT
            p.*,
            j.nombre_jugador,
            c.nombre AS categoria_nombre,
            tp.nombre AS tipo_pago_nombre,
            sp.nombre AS situacion_pago_nombre,
            mp.nombre AS medio_pago_nombre
          FROM pagos_jugador p
          JOIN jugadores j
            ON j.rut_jugador = p.jugador_rut
          LEFT JOIN categorias c
            ON c.id = j.categoria_id
          LEFT JOIN tipo_pago tp
            ON tp.id = p.tipo_pago_id
          LEFT JOIN academia_tipo_pago atp
            ON atp.academia_id = j.academia_id
           AND atp.tipo_pago_id = p.tipo_pago_id
          LEFT JOIN situacion_pago sp
            ON sp.id = p.situacion_pago_id
          LEFT JOIN medio_pago mp
            ON mp.id = p.medio_pago_id
          WHERE j.academia_id = ?
          ORDER BY p.fecha_pago DESC, p.id DESC
        `,
        [academia_id]
      );

      reply.header("Cache-Control", "no-store");

      return reply.send({
        ok: true,
        academia_id,
        items: rows ?? [],
      });
    } catch (err: any) {
      const code = err?.statusCode && Number.isFinite(err.statusCode) ? err.statusCode : 500;
      reply.header("Cache-Control", "no-store");
      return reply.code(code).send({
        ok: false,
        message: "Error al obtener estado de cuenta",
        detail: err?.message,
      });
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
      const academia_id = resolveAcademiaId(req);

      const [rows] = await db.query(
        `
        SELECT
          p.*,
          tp.nombre AS tipo_pago_nombre,
          sp.nombre AS situacion_pago_nombre,
          mp.nombre AS medio_pago_nombre
        FROM pagos_jugador p
        JOIN jugadores j
          ON j.rut_jugador = p.jugador_rut
        LEFT JOIN tipo_pago tp
          ON tp.id = p.tipo_pago_id
        LEFT JOIN situacion_pago sp
          ON sp.id = p.situacion_pago_id
        LEFT JOIN medio_pago mp
          ON mp.id = p.medio_pago_id
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
      const academia_id = resolveAcademiaId(req);

      const [rows]: any = await db.query(
        `
        SELECT
          p.*,
          tp.nombre AS tipo_pago_nombre,
          sp.nombre AS situacion_pago_nombre,
          mp.nombre AS medio_pago_nombre
        FROM pagos_jugador p
        JOIN jugadores j
          ON j.rut_jugador = p.jugador_rut
        LEFT JOIN tipo_pago tp
          ON tp.id = p.tipo_pago_id
        LEFT JOIN situacion_pago sp
          ON sp.id = p.situacion_pago_id
        LEFT JOIN medio_pago mp
          ON mp.id = p.medio_pago_id
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
      const academia_id = resolveAcademiaId(req);

      await assertJugadorInAcademiaOrThrow(data.jugador_rut, academia_id);
      await assertTipoPagoEnabledOrThrow(data.tipo_pago_id, academia_id);
      await assertSituacionPagoExistsOrThrow(data.situacion_pago_id, academia_id);

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
      const academia_id = resolveAcademiaId(req);

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

      if (data.tipo_pago_id) {
        await assertTipoPagoEnabledOrThrow(Number(data.tipo_pago_id), academia_id);
      }

      if (data.situacion_pago_id) {
        await assertSituacionPagoExistsOrThrow(Number(data.situacion_pago_id), academia_id);
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
      const academia_id = resolveAcademiaId(req);

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
