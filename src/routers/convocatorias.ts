// src/routers/convocatorias.ts

import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";

import { z } from "zod";
import { db } from "../db";

import { decryptRut, rutBlindIndex } from "../services/crypto";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/* =========================================================
   HELPERS
========================================================= */

const b2i = (value: boolean | number | undefined | null) => (value ? 1 : 0);

const i2b = (value: any) => (Number(value) ? true : false);

const getErrorCode = (err: any) =>
  err?.statusCode && Number.isFinite(Number(err.statusCode)) ? Number(err.statusCode) : 500;

/* =========================================================
   SCHEMAS
========================================================= */

const ConvocatoriaSchema = z.object({
  /*
   * Se conserva jugador_rut como contrato HTTP.
   *
   * Internamente NO se guarda en convocatorias.
   * Se resuelve a jugadores.id.
   */
  jugador_rut: z.number().int().positive(),

  fecha_partido: z.string().refine((value) => !Number.isNaN(Date.parse(value)), "fecha_partido inválida"),

  evento_id: z.number().int().positive(),

  asistio: z.boolean().optional().default(false),

  titular: z.boolean().optional().default(false),

  observaciones: z.string().nullable().optional(),
});

const OneOrManySchema = z.union([ConvocatoriaSchema, z.array(ConvocatoriaSchema).min(1)]);

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const EventoParam = z.object({
  evento_id: z.coerce.number().int().positive(),
});

const ConvocatoriaParam = z.object({
  evento_id: z.coerce.number().int().positive(),

  convocatoria_id: z.coerce.number().int().positive(),
});

const PaginationQuery = z.object({
  page: z.coerce.number().int().positive().optional(),

  pageSize: z.coerce.number().int().positive().optional(),
});

/* =========================================================
   EVENTO EN ACADEMIA
========================================================= */

async function assertEventoInAcademiaOrReply(
  evento_id: number,
  academia_id: number,
  reply: FastifyReply
): Promise<boolean> {
  const [rows]: any = await db.query(
    `
      SELECT id
      FROM eventos
      WHERE id = ?
        AND academia_id = ?
      LIMIT 1
    `,
    [evento_id, academia_id]
  );

  if (!rows?.length) {
    reply.code(403).send({
      ok: false,
      message: "FORBIDDEN_EVENTO",
    });

    return false;
  }

  return true;
}

/* =========================================================
   RESOLVER JUGADORES POR RUT

   Frontend:
   jugador_rut

        ↓

   rutBlindIndex()

        ↓

   jugadores.rut_jugador_idx

        ↓

   jugadores.id

        ↓

   convocatorias.jugador_id
========================================================= */

async function resolveJugadoresInAcademiaOrReply(
  jugadorRuts: number[],
  academia_id: number,
  reply: FastifyReply
): Promise<Map<number, number> | null> {
  const uniqueRuts = Array.from(new Set(jugadorRuts.map(Number))).filter(
    (rut) => Number.isInteger(rut) && rut >= 1_000_000 && rut <= 99_999_999
  );

  if (!uniqueRuts.length) {
    reply.code(400).send({
      ok: false,
      message: "No existen jugadores válidos para convocar",
    });

    return null;
  }

  const indexes = uniqueRuts.map((rut) => rutBlindIndex(rut));

  const placeholders = indexes.map(() => "?").join(", ");

  const [rows]: any = await db.query(
    `
      SELECT
        id,
        rut_jugador_enc
      FROM jugadores
      WHERE academia_id = ?
        AND rut_jugador_idx IN (${placeholders})
    `,
    [academia_id, ...indexes]
  );

  const jugadoresPorRut = new Map<number, number>();

  for (const row of rows ?? []) {
    if (!row?.rut_jugador_enc) {
      continue;
    }

    const decrypted = decryptRut(row.rut_jugador_enc);

    const rut = decrypted ? Number(decrypted) : 0;

    const jugadorId = Number(row.id);

    if (Number.isInteger(rut) && rut > 0 && Number.isInteger(jugadorId) && jugadorId > 0) {
      jugadoresPorRut.set(rut, jugadorId);
    }
  }

  const faltantes = uniqueRuts.filter((rut) => !jugadoresPorRut.has(rut));

  if (faltantes.length) {
    /*
     * No se exponen los RUT faltantes.
     *
     * Así evitamos filtrar información
     * cross-tenant.
     */
    reply.code(403).send({
      ok: false,
      message: "Uno o más jugadores no pertenecen a la academia seleccionada",
    });

    return null;
  }

  return jugadoresPorRut;
}

/* =========================================================
   VALIDAR CONVOCATORIA POR ACADEMIA
========================================================= */

async function assertConvocatoriaIdInAcademiaOrReply(
  id: number,
  academia_id: number,
  reply: FastifyReply
): Promise<boolean> {
  const [rows]: any = await db.query(
    `
      SELECT c.id
      FROM convocatorias c

      INNER JOIN eventos e
        ON e.id = c.evento_id

      WHERE c.id = ?
        AND c.academia_id = ?
        AND e.academia_id = ?

      LIMIT 1
    `,
    [id, academia_id, academia_id]
  );

  if (!rows?.length) {
    /*
     * 404 para no revelar existencia
     * de registros cross-tenant.
     */
    reply.code(404).send({
      ok: false,
      message: "No encontrado",
    });

    return false;
  }

  return true;
}

/* =========================================================
   NORMALIZAR SALIDA

   La BD trabaja con jugador_id.

   Al frontend se devuelve además jugador_rut
   descifrado para mantener compatibilidad.
========================================================= */

function normalizeConvocatoriaOut(row: any) {
  if (!row) {
    return null;
  }

  let jugadorRut: number | null = null;

  if (row.rut_jugador_enc) {
    const decrypted = decryptRut(row.rut_jugador_enc);

    if (decrypted) {
      const parsed = Number(decrypted);

      jugadorRut = Number.isInteger(parsed) && parsed > 0 ? parsed : null;
    }
  }

  const { rut_jugador_enc, ...safeRow } = row;

  return {
    ...safeRow,

    jugador_rut: jugadorRut,

    asistio: i2b(row.asistio),

    titular: i2b(row.titular),
  };
}

/* =========================================================
   SELECT BASE
========================================================= */

const CONVOCATORIA_SELECT = `
  SELECT
    c.id,
    c.academia_id,
    c.jugador_id,

    j.rut_jugador_enc,

    c.fecha_partido,
    c.evento_id,
    c.convocatoria_id,
    c.asistio,
    c.titular,
    c.observaciones

  FROM convocatorias c

  INNER JOIN eventos e
    ON e.id = c.evento_id
   AND e.academia_id = c.academia_id

  INNER JOIN jugadores j
    ON j.id = c.jugador_id
   AND j.academia_id = c.academia_id
`;

/* =========================================================
   ROUTER
========================================================= */

export default async function convocatorias(app: FastifyInstance) {
  /*
   * Se mantiene la política
   * original del módulo.
   */
  const canRead = [requireAuth, requireRoles([1, 3])];

  const canWrite = [requireAuth, requireRoles([1, 3])];

  /* =======================================================
     HEALTH
  ======================================================= */

  app.get(
    "/health",
    {
      preHandler: canRead,
    },
    async () => ({
      module: "convocatorias",
      status: "ready",
      timestamp: new Date().toISOString(),
    })
  );

  /* =======================================================
     GET TODAS
  ======================================================= */

  app.get(
    "/",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const parsedQuery = PaginationQuery.safeParse(req.query);

        const page = parsedQuery.success && parsedQuery.data.page ? Number(parsedQuery.data.page) : 1;

        const pageSize =
          parsedQuery.success && parsedQuery.data.pageSize ? Math.min(Number(parsedQuery.data.pageSize), 200) : 50;

        const safePage = Math.max(page, 1);

        const limit = Math.min(Math.max(pageSize, 1), 200);

        const offset = (safePage - 1) * limit;

        const academia_id = getEffectiveAcademiaId(req);

        const [rows]: any = await db.query(
          `
              ${CONVOCATORIA_SELECT}

              WHERE c.academia_id = ?
                AND e.academia_id = ?

              ORDER BY
                c.fecha_partido DESC,
                c.id DESC

              LIMIT ?
              OFFSET ?
            `,
          [academia_id, academia_id, limit, offset]
        );

        const items = (rows ?? []).map(normalizeConvocatoriaOut);

        return reply.send({
          ok: true,
          items,
          page: safePage,
          pageSize: limit,
          academia_id,
        });
      } catch (err: any) {
        return reply.code(getErrorCode(err)).send({
          ok: false,

          message: "Error al listar convocatorias",

          error: err?.message,
        });
      }
    }
  );

  /* =======================================================
     GET POR EVENTO
  ======================================================= */

  app.get(
    "/evento/:evento_id",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsedParams = EventoParam.safeParse(req.params);

      if (!parsedParams.success) {
        return reply.code(400).send({
          ok: false,
          message: "evento_id inválido",
        });
      }

      const parsedQuery = PaginationQuery.safeParse(req.query);

      const page = parsedQuery.success && parsedQuery.data.page ? Number(parsedQuery.data.page) : 1;

      const pageSize =
        parsedQuery.success && parsedQuery.data.pageSize ? Math.min(Number(parsedQuery.data.pageSize), 200) : 50;

      const safePage = Math.max(page, 1);

      const limit = Math.min(Math.max(pageSize, 1), 200);

      const offset = (safePage - 1) * limit;

      const evento_id = parsedParams.data.evento_id;

      try {
        const academia_id = getEffectiveAcademiaId(req);

        const okEvento = await assertEventoInAcademiaOrReply(evento_id, academia_id, reply);

        if (!okEvento) {
          return;
        }

        const [rows]: any = await db.query(
          `
              ${CONVOCATORIA_SELECT}

              WHERE c.evento_id = ?
                AND c.academia_id = ?
                AND e.academia_id = ?

              ORDER BY
                c.fecha_partido DESC,
                c.id DESC

              LIMIT ?
              OFFSET ?
            `,
          [evento_id, academia_id, academia_id, limit, offset]
        );

        const items = (rows ?? []).map(normalizeConvocatoriaOut);

        return reply.send({
          ok: true,
          items,
          page: safePage,
          pageSize: limit,
          academia_id,
        });
      } catch (err: any) {
        return reply.code(getErrorCode(err)).send({
          ok: false,

          message: "Error al listar por evento",

          error: err?.message,
        });
      }
    }
  );

  /* =======================================================
     GET EVENTO + CONVOCATORIA_ID

     Es el endpoint utilizado por
     verConvocacionHistorica.jsx
  ======================================================= */

  app.get(
    "/evento/:evento_id/convocatoria/:convocatoria_id",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsedParams = ConvocatoriaParam.safeParse(req.params);

      if (!parsedParams.success) {
        return reply.code(400).send({
          ok: false,
          message: "Parámetros inválidos",
        });
      }

      const { evento_id, convocatoria_id } = parsedParams.data;

      try {
        const academia_id = getEffectiveAcademiaId(req);

        const okEvento = await assertEventoInAcademiaOrReply(evento_id, academia_id, reply);

        if (!okEvento) {
          return;
        }

        const [rows]: any = await db.query(
          `
              ${CONVOCATORIA_SELECT}

              WHERE c.evento_id = ?
                AND c.convocatoria_id = ?
                AND c.academia_id = ?
                AND e.academia_id = ?

              ORDER BY
                c.jugador_id ASC
            `,
          [evento_id, convocatoria_id, academia_id, academia_id]
        );

        const items = (rows ?? [])
          .map(normalizeConvocatoriaOut)
          .sort((a: any, b: any) => Number(a?.jugador_rut ?? 0) - Number(b?.jugador_rut ?? 0));

        return reply.send({
          ok: true,
          items,
          academia_id,
        });
      } catch (err: any) {
        return reply.code(getErrorCode(err)).send({
          ok: false,

          message: "Error al obtener jugadores de la convocatoria",

          error: err?.message,
        });
      }
    }
  );

  /* =======================================================
     GET POR ID
  ======================================================= */

  app.get(
    "/:id",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse(req.params);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      const id = parsed.data.id;

      try {
        const academia_id = getEffectiveAcademiaId(req);

        const [rows]: any = await db.query(
          `
              ${CONVOCATORIA_SELECT}

              WHERE c.id = ?
                AND c.academia_id = ?
                AND e.academia_id = ?

              LIMIT 1
            `,
          [id, academia_id, academia_id]
        );

        if (!rows?.length) {
          return reply.code(404).send({
            ok: false,
            message: "No encontrado",
          });
        }

        return reply.send({
          ok: true,

          item: normalizeConvocatoriaOut(rows[0]),

          academia_id,
        });
      } catch (err: any) {
        return reply.code(getErrorCode(err)).send({
          ok: false,

          message: "Error al obtener convocatoria",

          error: err?.message,
        });
      }
    }
  );

  /* =======================================================
     POST
  ======================================================= */

  app.post(
    "/",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      /*
       * Payload máximo 1 MB.
       */
      const sizeBytes = Buffer.byteLength(JSON.stringify(req.body ?? {}));

      if (sizeBytes > 1024 * 1024) {
        return reply.code(413).send({
          ok: false,
          message: "Payload demasiado grande (máx 1 MB)",
        });
      }

      const parsed = OneOrManySchema.safeParse(req.body);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,

          message: "Payload inválido",

          errors: parsed.error.flatten(),
        });
      }

      const data = Array.isArray(parsed.data) ? parsed.data : [parsed.data];

      if (data.length > 100) {
        return reply.code(413).send({
          ok: false,

          message: `Listado demasiado grande (${data.length}). Máximo = 100.`,
        });
      }

      /*
       * Una creación masiva
       * pertenece a un único evento.
       */
      const eventoIds = Array.from(new Set(data.map((item) => item.evento_id)));

      if (eventoIds.length !== 1) {
        return reply.code(400).send({
          ok: false,

          message: "Todos los registros deben tener el mismo evento_id",
        });
      }

      const evento_id = eventoIds[0];

      try {
        /* -------------------------
           TENANT
        ------------------------- */

        const academia_id = getEffectiveAcademiaId(req);

        /* -------------------------
           EVENTO
        ------------------------- */

        const okEvento = await assertEventoInAcademiaOrReply(evento_id, academia_id, reply);

        if (!okEvento) {
          return;
        }

        /* -------------------------
           RESOLVER JUGADORES
        ------------------------- */

        const jugadoresPorRut = await resolveJugadoresInAcademiaOrReply(
          data.map((item) => item.jugador_rut),
          academia_id,
          reply
        );

        if (!jugadoresPorRut) {
          return;
        }

        /* -------------------------
           SIGUIENTE CONVOCATORIA
        ------------------------- */

        const [rowsMax]: any = await db.query(
          `
              SELECT
                COALESCE(
                  MAX(c.convocatoria_id),
                  0
                ) AS maxConv

              FROM convocatorias c

              INNER JOIN eventos e
                ON e.id = c.evento_id

              WHERE c.evento_id = ?
                AND c.academia_id = ?
                AND e.academia_id = ?
            `,
          [evento_id, academia_id, academia_id]
        );

        const nextConvId = Number(rowsMax?.[0]?.maxConv ?? 0) + 1;

        /* -------------------------
           VALUES

           En DB se inserta
           jugador_id.
        ------------------------- */

        const values = data.map((item) => {
          const jugadorId = jugadoresPorRut.get(Number(item.jugador_rut));

          if (!jugadorId) {
            throw new Error("No fue posible resolver el jugador de la convocatoria");
          }

          return [
            academia_id,
            jugadorId,
            item.fecha_partido,
            item.evento_id,
            nextConvId,
            b2i(item.asistio),
            b2i(item.titular),
            item.observaciones ?? null,
          ];
        });

        /* -------------------------
           INSERT
        ------------------------- */

        await db.query(
          `
            INSERT INTO convocatorias
            (
              academia_id,
              jugador_id,
              fecha_partido,
              evento_id,
              convocatoria_id,
              asistio,
              titular,
              observaciones
            )
            VALUES ?
          `,
          [values]
        );

        return reply.code(201).send({
          ok: true,

          evento_id,

          convocatoria_id: nextConvId,

          inserted: values.length,

          academia_id,
        });
      } catch (err: any) {
        return reply.code(getErrorCode(err)).send({
          ok: false,

          message: "Error al crear convocatoria(s)",

          error: err?.message,
        });
      }
    }
  );

  /* =======================================================
     PUT
  ======================================================= */

  app.put(
    "/:id",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const idParsed = IdParam.safeParse(req.params);

      if (!idParsed.success) {
        return reply.code(400).send({
          ok: false,

          message: "ID inválido",
        });
      }

      const bodyParsed = ConvocatoriaSchema.partial().safeParse(req.body);

      if (!bodyParsed.success) {
        return reply.code(400).send({
          ok: false,

          message: "Payload inválido",

          errors: bodyParsed.error.flatten(),
        });
      }

      const id = idParsed.data.id;

      const data = bodyParsed.data;

      try {
        const academia_id = getEffectiveAcademiaId(req);

        /* -------------------------
           FILA / TENANT
        ------------------------- */

        const okRow = await assertConvocatoriaIdInAcademiaOrReply(id, academia_id, reply);

        if (!okRow) {
          return;
        }

        /* -------------------------
           NUEVO EVENTO
        ------------------------- */

        if (data.evento_id !== undefined) {
          const okEvento = await assertEventoInAcademiaOrReply(Number(data.evento_id), academia_id, reply);

          if (!okEvento) {
            return;
          }
        }

        /* -------------------------
           NUEVO JUGADOR

           jugador_rut →
           jugador_id
        ------------------------- */

        let nuevoJugadorId: number | null = null;

        if (data.jugador_rut !== undefined) {
          const jugadoresPorRut = await resolveJugadoresInAcademiaOrReply(
            [Number(data.jugador_rut)],
            academia_id,
            reply
          );

          if (!jugadoresPorRut) {
            return;
          }

          nuevoJugadorId = jugadoresPorRut.get(Number(data.jugador_rut)) ?? null;

          if (!nuevoJugadorId) {
            return reply.code(400).send({
              ok: false,

              message: "No fue posible resolver el jugador",
            });
          }
        }

        /* -------------------------
           UPDATE DINÁMICO
        ------------------------- */

        const fields: string[] = [];

        const values: any[] = [];

        if (data.jugador_rut !== undefined) {
          fields.push("jugador_id = ?");

          values.push(nuevoJugadorId);
        }

        if (data.fecha_partido !== undefined) {
          fields.push("fecha_partido = ?");

          values.push(data.fecha_partido);
        }

        if (data.evento_id !== undefined) {
          fields.push("evento_id = ?");

          values.push(data.evento_id);
        }

        if (data.asistio !== undefined) {
          fields.push("asistio = ?");

          values.push(b2i(data.asistio));
        }

        if (data.titular !== undefined) {
          fields.push("titular = ?");

          values.push(b2i(data.titular));
        }

        if (data.observaciones !== undefined) {
          fields.push("observaciones = ?");

          values.push(data.observaciones ?? null);
        }

        if (fields.length === 0) {
          return reply.code(400).send({
            ok: false,

            message: "No hay campos para actualizar",
          });
        }

        /*
         * academia_id no es editable.
         * Se usa como condición.
         */
        const [result]: any = await db.query(
          `
              UPDATE convocatorias

              SET ${fields.join(", ")}

              WHERE id = ?
                AND academia_id = ?
            `,
          [...values, id, academia_id]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,

            message: "No encontrado",
          });
        }

        return reply.send({
          ok: true,

          updated: {
            id,
            ...data,

            /*
             * Se devuelve también
             * el ID técnico para
             * consumidores futuros.
             */
            ...(nuevoJugadorId
              ? {
                  jugador_id: nuevoJugadorId,
                }
              : {}),
          },

          academia_id,
        });
      } catch (err: any) {
        return reply.code(getErrorCode(err)).send({
          ok: false,

          message: "Error al actualizar",

          error: err?.message,
        });
      }
    }
  );

  /* =======================================================
     DELETE
  ======================================================= */

  app.delete(
    "/:id",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse(req.params);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,

          message: "ID inválido",
        });
      }

      const id = parsed.data.id;

      try {
        const academia_id = getEffectiveAcademiaId(req);

        const okRow = await assertConvocatoriaIdInAcademiaOrReply(id, academia_id, reply);

        if (!okRow) {
          return;
        }

        /*
         * Segunda protección:
         *
         * DELETE condicionado
         * por academia_id.
         */
        const [result]: any = await db.query(
          `
              DELETE
              FROM convocatorias

              WHERE id = ?
                AND academia_id = ?
            `,
          [id, academia_id]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,

            message: "No encontrado",
          });
        }

        return reply.send({
          ok: true,
          deleted: id,
          academia_id,
        });
      } catch (err: any) {
        return reply.code(getErrorCode(err)).send({
          ok: false,

          message: "Error al eliminar",

          error: err?.message,
        });
      }
    }
  );
}
