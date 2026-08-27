// src/routers/convocatorias.ts
import type {
  FastifyInstance,
  FastifyRequest,
  FastifyReply,
} from "fastify";

import { z } from "zod";
import { db } from "../db";

import {
  requireAuth,
  requireRoles,
  getEffectiveAcademiaId,
} from "../middlewares/authz";

/* =========================================================
   Helpers
========================================================= */

const b2i = (
  value: boolean | number | undefined | null
) => (value ? 1 : 0);

const i2b = (value: any) =>
  Number(value) ? true : false;

const getErrorCode = (err: any) =>
  err?.statusCode &&
  Number.isFinite(Number(err.statusCode))
    ? Number(err.statusCode)
    : 500;

/* =========================================================
   Validadores
========================================================= */

const ConvocatoriaSchema = z.object({
  jugador_rut: z
    .number()
    .int()
    .positive(),

  fecha_partido: z
    .string()
    .refine(
      (value) =>
        !Number.isNaN(
          Date.parse(value)
        ),
      "fecha_partido inválida"
    ),

  evento_id: z
    .number()
    .int()
    .positive(),

  asistio: z
    .boolean()
    .optional()
    .default(false),

  titular: z
    .boolean()
    .optional()
    .default(false),

  observaciones: z
    .string()
    .nullable()
    .optional(),
});

const OneOrManySchema = z.union([
  ConvocatoriaSchema,

  z
    .array(ConvocatoriaSchema)
    .min(1),
]);

const IdParam = z.object({
  id: z.coerce
    .number()
    .int()
    .positive(),
});

const EventoParam = z.object({
  evento_id: z.coerce
    .number()
    .int()
    .positive(),
});

const ConvocatoriaParam =
  z.object({
    evento_id: z.coerce
      .number()
      .int()
      .positive(),

    convocatoria_id: z.coerce
      .number()
      .int()
      .positive(),
  });

const PaginationQuery =
  z.object({
    page: z.coerce
      .number()
      .int()
      .positive()
      .optional(),

    pageSize: z.coerce
      .number()
      .int()
      .positive()
      .optional(),
  });

/* =========================================================
   Validación de evento por academia
========================================================= */

async function assertEventoInAcademiaOrReply(
  evento_id: number,
  academia_id: number,
  reply: FastifyReply
): Promise<boolean> {
  const [rows]: any =
    await db.query(
      `
      SELECT id
        FROM eventos
       WHERE id = ?
         AND academia_id = ?
       LIMIT 1
      `,
      [
        evento_id,
        academia_id,
      ]
    );

  if (!rows?.length) {
    reply.code(403).send({
      ok: false,
      message:
        "FORBIDDEN_EVENTO",
    });

    return false;
  }

  return true;
}

/* =========================================================
   Validación de jugadores por academia

   Impide crear una convocatoria con un jugador
   perteneciente a otra academia.
========================================================= */

async function assertJugadoresInAcademiaOrReply(
  jugadorRuts: number[],
  academia_id: number,
  reply: FastifyReply
): Promise<boolean> {
  const uniqueRuts =
    Array.from(
      new Set(
        jugadorRuts.map(Number)
      )
    ).filter(
      (rut) =>
        Number.isFinite(rut) &&
        rut > 0
    );

  if (!uniqueRuts.length) {
    reply.code(400).send({
      ok: false,
      message:
        "No existen jugadores válidos para convocar",
    });

    return false;
  }

  const placeholders =
    uniqueRuts
      .map(() => "?")
      .join(", ");

  const [rows]: any =
    await db.query(
      `
      SELECT rut_jugador
        FROM jugadores
       WHERE academia_id = ?
         AND rut_jugador IN (${placeholders})
      `,
      [
        academia_id,
        ...uniqueRuts,
      ]
    );

  const encontrados =
    new Set(
      (rows ?? []).map(
        (row: any) =>
          Number(
            row.rut_jugador
          )
      )
    );

  const faltantes =
    uniqueRuts.filter(
      (rut) =>
        !encontrados.has(rut)
    );

  if (faltantes.length) {
    /*
     * No retornamos los RUT faltantes
     * para evitar filtrar información
     * cross-tenant.
     */
    reply.code(403).send({
      ok: false,
      message:
        "Uno o más jugadores no pertenecen a la academia seleccionada",
    });

    return false;
  }

  return true;
}

/* =========================================================
   Validación convocatoria por academia

   Se valida:
   - convocatorias.academia_id
   - eventos.academia_id

   Esto entrega doble aislamiento tenant.
========================================================= */

async function assertConvocatoriaIdInAcademiaOrReply(
  id: number,
  academia_id: number,
  reply: FastifyReply
): Promise<boolean> {
  const [rows]: any =
    await db.query(
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
      [
        id,
        academia_id,
        academia_id,
      ]
    );

  if (!rows?.length) {
    /*
     * 404 y no 403:
     * evita revelar existencia de
     * registros cross-tenant.
     */
    reply.code(404).send({
      ok: false,
      message:
        "No encontrado",
    });

    return false;
  }

  return true;
}

/* =========================================================
   ROUTER
========================================================= */

export default async function convocatorias(
  app: FastifyInstance
) {
  /*
   * Mantenemos exactamente la política
   * que ya tenía este módulo.
   */
  const canRead = [
    requireAuth,
    requireRoles([1, 3]),
  ];

  const canWrite = [
    requireAuth,
    requireRoles([1, 3]),
  ];

  /* =======================================================
     HEALTH
  ======================================================= */

  app.get(
    "/health",
    {
      preHandler: canRead,
    },
    async () => ({
      module:
        "convocatorias",

      status:
        "ready",

      timestamp:
        new Date().toISOString(),
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
    async (
      req: FastifyRequest,
      reply: FastifyReply
    ) => {
      try {
        const parsedQuery =
          PaginationQuery.safeParse(
            req.query
          );

        const page =
          parsedQuery.success &&
          parsedQuery.data.page
            ? Number(
                parsedQuery.data.page
              )
            : 1;

        const pageSize =
          parsedQuery.success &&
          parsedQuery.data.pageSize
            ? Math.min(
                Number(
                  parsedQuery.data
                    .pageSize
                ),
                200
              )
            : 50;

        const safePage =
          Math.max(
            page,
            1
          );

        const limit =
          Math.min(
            Math.max(
              pageSize,
              1
            ),
            200
          );

        const offset =
          (safePage - 1) *
          limit;

        const academia_id =
          getEffectiveAcademiaId(
            req
          );

        const [rows] =
          await db.query(
            `
            SELECT
              c.id,
              c.academia_id,
              c.jugador_rut,
              c.fecha_partido,
              c.evento_id,
              c.convocatoria_id,
              c.asistio,
              c.titular,
              c.observaciones

              FROM convocatorias c

              INNER JOIN eventos e
                ON e.id = c.evento_id

             WHERE c.academia_id = ?
               AND e.academia_id = ?

             ORDER BY
               c.fecha_partido DESC,
               c.id DESC

             LIMIT ?
            OFFSET ?
            `,
            [
              academia_id,
              academia_id,
              limit,
              offset,
            ]
          );

        const items =
          (rows as any[]).map(
            (row) => ({
              ...row,

              asistio:
                i2b(
                  row.asistio
                ),

              titular:
                i2b(
                  row.titular
                ),
            })
          );

        return reply.send({
          ok: true,
          items,
          page: safePage,
          pageSize: limit,
          academia_id,
        });
      } catch (err: any) {
        return reply
          .code(
            getErrorCode(err)
          )
          .send({
            ok: false,

            message:
              "Error al listar convocatorias",

            error:
              err?.message,
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
    async (
      req: FastifyRequest,
      reply: FastifyReply
    ) => {
      const parsedParams =
        EventoParam.safeParse(
          req.params
        );

      if (
        !parsedParams.success
      ) {
        return reply
          .code(400)
          .send({
            ok: false,
            message:
              "evento_id inválido",
          });
      }

      const parsedQuery =
        PaginationQuery.safeParse(
          req.query
        );

      const page =
        parsedQuery.success &&
        parsedQuery.data.page
          ? Number(
              parsedQuery.data.page
            )
          : 1;

      const pageSize =
        parsedQuery.success &&
        parsedQuery.data.pageSize
          ? Math.min(
              Number(
                parsedQuery.data
                  .pageSize
              ),
              200
            )
          : 50;

      const safePage =
        Math.max(page, 1);

      const limit =
        Math.min(
          Math.max(
            pageSize,
            1
          ),
          200
        );

      const offset =
        (safePage - 1) *
        limit;

      const evento_id =
        parsedParams.data
          .evento_id;

      try {
        const academia_id =
          getEffectiveAcademiaId(
            req
          );

        const okEvento =
          await assertEventoInAcademiaOrReply(
            evento_id,
            academia_id,
            reply
          );

        if (!okEvento) {
          return;
        }

        const [rows] =
          await db.query(
            `
            SELECT
              c.id,
              c.academia_id,
              c.jugador_rut,
              c.fecha_partido,
              c.evento_id,
              c.convocatoria_id,
              c.asistio,
              c.titular,
              c.observaciones

              FROM convocatorias c

              INNER JOIN eventos e
                ON e.id = c.evento_id

             WHERE c.evento_id = ?
               AND c.academia_id = ?
               AND e.academia_id = ?

             ORDER BY
               c.fecha_partido DESC,
               c.id DESC

             LIMIT ?
            OFFSET ?
            `,
            [
              evento_id,
              academia_id,
              academia_id,
              limit,
              offset,
            ]
          );

        const items =
          (rows as any[]).map(
            (row) => ({
              ...row,

              asistio:
                i2b(
                  row.asistio
                ),

              titular:
                i2b(
                  row.titular
                ),
            })
          );

        return reply.send({
          ok: true,
          items,
          page: safePage,
          pageSize: limit,
          academia_id,
        });
      } catch (err: any) {
        return reply
          .code(
            getErrorCode(err)
          )
          .send({
            ok: false,

            message:
              "Error al listar por evento",

            error:
              err?.message,
          });
      }
    }
  );

  /* =======================================================
     GET EVENTO + CONVOCATORIA_ID
  ======================================================= */

  app.get(
    "/evento/:evento_id/convocatoria/:convocatoria_id",
    {
      preHandler: canRead,
    },
    async (
      req: FastifyRequest,
      reply: FastifyReply
    ) => {
      const parsedParams =
        ConvocatoriaParam.safeParse(
          req.params
        );

      if (
        !parsedParams.success
      ) {
        return reply
          .code(400)
          .send({
            ok: false,
            message:
              "Parámetros inválidos",
          });
      }

      const {
        evento_id,
        convocatoria_id,
      } =
        parsedParams.data;

      try {
        const academia_id =
          getEffectiveAcademiaId(
            req
          );

        const okEvento =
          await assertEventoInAcademiaOrReply(
            evento_id,
            academia_id,
            reply
          );

        if (!okEvento) {
          return;
        }

        const [rows]: any =
          await db.query(
            `
            SELECT
              c.id,
              c.academia_id,
              c.jugador_rut,
              c.fecha_partido,
              c.evento_id,
              c.convocatoria_id,
              c.asistio,
              c.titular,
              c.observaciones

              FROM convocatorias c

              INNER JOIN eventos e
                ON e.id = c.evento_id

             WHERE c.evento_id = ?
               AND c.convocatoria_id = ?
               AND c.academia_id = ?
               AND e.academia_id = ?

             ORDER BY
               c.jugador_rut ASC
            `,
            [
              evento_id,
              convocatoria_id,
              academia_id,
              academia_id,
            ]
          );

        const items =
          (rows ?? []).map(
            (row: any) => ({
              ...row,

              asistio:
                i2b(
                  row.asistio
                ),

              titular:
                i2b(
                  row.titular
                ),
            })
          );

        return reply.send({
          ok: true,
          items,
          academia_id,
        });
      } catch (err: any) {
        return reply
          .code(
            getErrorCode(err)
          )
          .send({
            ok: false,

            message:
              "Error al obtener jugadores de la convocatoria",

            error:
              err?.message,
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
    async (
      req: FastifyRequest,
      reply: FastifyReply
    ) => {
      const parsed =
        IdParam.safeParse(
          req.params
        );

      if (!parsed.success) {
        return reply
          .code(400)
          .send({
            ok: false,
            message:
              "ID inválido",
          });
      }

      const id =
        parsed.data.id;

      try {
        const academia_id =
          getEffectiveAcademiaId(
            req
          );

        const [rows]: any =
          await db.query(
            `
            SELECT
              c.id,
              c.academia_id,
              c.jugador_rut,
              c.fecha_partido,
              c.evento_id,
              c.convocatoria_id,
              c.asistio,
              c.titular,
              c.observaciones

              FROM convocatorias c

              INNER JOIN eventos e
                ON e.id = c.evento_id

             WHERE c.id = ?
               AND c.academia_id = ?
               AND e.academia_id = ?

             LIMIT 1
            `,
            [
              id,
              academia_id,
              academia_id,
            ]
          );

        if (!rows?.length) {
          return reply
            .code(404)
            .send({
              ok: false,
              message:
                "No encontrado",
            });
        }

        const row =
          rows[0];

        return reply.send({
          ok: true,

          item: {
            ...row,

            asistio:
              i2b(
                row.asistio
              ),

            titular:
              i2b(
                row.titular
              ),
          },

          academia_id,
        });
      } catch (err: any) {
        return reply
          .code(
            getErrorCode(err)
          )
          .send({
            ok: false,

            message:
              "Error al obtener convocatoria",

            error:
              err?.message,
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
    async (
      req: FastifyRequest,
      reply: FastifyReply
    ) => {
      /* ─────────────────────
         Payload máximo 1 MB
      ───────────────────── */

      const sizeBytes =
        Buffer.byteLength(
          JSON.stringify(
            req.body ?? {}
          )
        );

      if (
        sizeBytes >
        1024 * 1024
      ) {
        return reply
          .code(413)
          .send({
            ok: false,

            message:
              "Payload demasiado grande (máx 1 MB)",
          });
      }

      /* ─────────────────────
         Validación Zod
      ───────────────────── */

      const parsed =
        OneOrManySchema.safeParse(
          req.body
        );

      if (!parsed.success) {
        return reply
          .code(400)
          .send({
            ok: false,

            message:
              "Payload inválido",

            errors:
              parsed.error.flatten(),
          });
      }

      const data =
        Array.isArray(
          parsed.data
        )
          ? parsed.data
          : [parsed.data];

      if (
        data.length > 100
      ) {
        return reply
          .code(413)
          .send({
            ok: false,

            message:
              `Listado demasiado grande (${data.length}). Máximo = 100.`,
          });
      }

      /*
       * Una misma creación masiva
       * debe pertenecer a un solo evento.
       */
      const eventoIds =
        Array.from(
          new Set(
            data.map(
              (item) =>
                item.evento_id
            )
          )
        );

      if (
        eventoIds.length !== 1
      ) {
        return reply
          .code(400)
          .send({
            ok: false,

            message:
              "Todos los registros deben tener el mismo evento_id",
          });
      }

      const evento_id =
        eventoIds[0];

      try {
        /* ===============================================
           TENANT
        =============================================== */

        const academia_id =
          getEffectiveAcademiaId(
            req
          );

        /* ===============================================
           EVENTO DEBE PERTENECER A LA ACADEMIA
        =============================================== */

        const okEvento =
          await assertEventoInAcademiaOrReply(
            evento_id,
            academia_id,
            reply
          );

        if (!okEvento) {
          return;
        }

        /* ===============================================
           TODOS LOS JUGADORES DEBEN PERTENECER
           A ESA MISMA ACADEMIA
        =============================================== */

        const okJugadores =
          await assertJugadoresInAcademiaOrReply(
            data.map(
              (item) =>
                item.jugador_rut
            ),
            academia_id,
            reply
          );

        if (!okJugadores) {
          return;
        }

        /* ===============================================
           SIGUIENTE convocatoria_id DEL EVENTO
        =============================================== */

        const [rowsMax]: any =
          await db.query(
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
            [
              evento_id,
              academia_id,
              academia_id,
            ]
          );

        const nextConvId =
          Number(
            rowsMax?.[0]
              ?.maxConv ??
              0
          ) + 1;

        /* ===============================================
           AQUÍ ESTABA EL ERROR ORIGINAL

           academia_id ahora forma parte de
           CADA fila insertada.
        =============================================== */

        const values =
          data.map(
            (item) => [
              academia_id,

              item.jugador_rut,

              item.fecha_partido,

              item.evento_id,

              nextConvId,

              b2i(
                item.asistio
              ),

              b2i(
                item.titular
              ),

              item.observaciones ??
                null,
            ]
          );

        /* ===============================================
           INSERT MULTIACADEMIA CORRECTO
        =============================================== */

        await db.query(
          `
          INSERT INTO convocatorias
          (
            academia_id,
            jugador_rut,
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

        return reply
          .code(201)
          .send({
            ok: true,

            evento_id,

            convocatoria_id:
              nextConvId,

            inserted:
              values.length,

            academia_id,
          });
      } catch (err: any) {
        return reply
          .code(
            getErrorCode(err)
          )
          .send({
            ok: false,

            message:
              "Error al crear convocatoria(s)",

            error:
              err?.message,
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
    async (
      req: FastifyRequest,
      reply: FastifyReply
    ) => {
      const idParsed =
        IdParam.safeParse(
          req.params
        );

      if (
        !idParsed.success
      ) {
        return reply
          .code(400)
          .send({
            ok: false,

            message:
              "ID inválido",
          });
      }

      const bodyParsed =
        ConvocatoriaSchema
          .partial()
          .safeParse(
            req.body
          );

      if (
        !bodyParsed.success
      ) {
        return reply
          .code(400)
          .send({
            ok: false,

            message:
              "Payload inválido",

            errors:
              bodyParsed.error.flatten(),
          });
      }

      const id =
        idParsed.data.id;

      const data =
        bodyParsed.data;

      try {
        const academia_id =
          getEffectiveAcademiaId(
            req
          );

        /* ===============================================
           La convocatoria debe pertenecer a la academia
        =============================================== */

        const okRow =
          await assertConvocatoriaIdInAcademiaOrReply(
            id,
            academia_id,
            reply
          );

        if (!okRow) {
          return;
        }

        /* ===============================================
           Si cambia evento, validar nuevo evento
        =============================================== */

        if (
          data.evento_id !==
          undefined
        ) {
          const okEvento =
            await assertEventoInAcademiaOrReply(
              Number(
                data.evento_id
              ),
              academia_id,
              reply
            );

          if (!okEvento) {
            return;
          }
        }

        /* ===============================================
           Si cambia jugador, validar jugador
        =============================================== */

        if (
          data.jugador_rut !==
          undefined
        ) {
          const okJugador =
            await assertJugadoresInAcademiaOrReply(
              [
                Number(
                  data.jugador_rut
                ),
              ],
              academia_id,
              reply
            );

          if (!okJugador) {
            return;
          }
        }

        const fields: string[] =
          [];

        const values: any[] =
          [];

        if (
          data.jugador_rut !==
          undefined
        ) {
          fields.push(
            "jugador_rut = ?"
          );

          values.push(
            data.jugador_rut
          );
        }

        if (
          data.fecha_partido !==
          undefined
        ) {
          fields.push(
            "fecha_partido = ?"
          );

          values.push(
            data.fecha_partido
          );
        }

        if (
          data.evento_id !==
          undefined
        ) {
          fields.push(
            "evento_id = ?"
          );

          values.push(
            data.evento_id
          );
        }

        if (
          data.asistio !==
          undefined
        ) {
          fields.push(
            "asistio = ?"
          );

          values.push(
            b2i(
              data.asistio
            )
          );
        }

        if (
          data.titular !==
          undefined
        ) {
          fields.push(
            "titular = ?"
          );

          values.push(
            b2i(
              data.titular
            )
          );
        }

        if (
          data.observaciones !==
          undefined
        ) {
          fields.push(
            "observaciones = ?"
          );

          values.push(
            data.observaciones ??
              null
          );
        }

        if (
          fields.length === 0
        ) {
          return reply
            .code(400)
            .send({
              ok: false,

              message:
                "No hay campos para actualizar",
            });
        }

        /*
         * Importante:
         * academia_id NO es editable.
         *
         * Solo se usa como condición.
         */
        const [result]: any =
          await db.query(
            `
            UPDATE convocatorias

               SET ${fields.join(
                 ", "
               )}

             WHERE id = ?
               AND academia_id = ?
            `,
            [
              ...values,
              id,
              academia_id,
            ]
          );

        if (
          Number(
            result?.affectedRows ??
              0
          ) === 0
        ) {
          return reply
            .code(404)
            .send({
              ok: false,
              message:
                "No encontrado",
            });
        }

        return reply.send({
          ok: true,

          updated: {
            id,
            ...data,
          },

          academia_id,
        });
      } catch (err: any) {
        return reply
          .code(
            getErrorCode(err)
          )
          .send({
            ok: false,

            message:
              "Error al actualizar",

            error:
              err?.message,
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
    async (
      req: FastifyRequest,
      reply: FastifyReply
    ) => {
      const parsed =
        IdParam.safeParse(
          req.params
        );

      if (!parsed.success) {
        return reply
          .code(400)
          .send({
            ok: false,
            message:
              "ID inválido",
          });
      }

      const id =
        parsed.data.id;

      try {
        const academia_id =
          getEffectiveAcademiaId(
            req
          );

        const okRow =
          await assertConvocatoriaIdInAcademiaOrReply(
            id,
            academia_id,
            reply
          );

        if (!okRow) {
          return;
        }

        /*
         * Segunda protección:
         * DELETE condicionado también
         * por academia_id.
         */
        const [result]: any =
          await db.query(
            `
            DELETE FROM convocatorias
             WHERE id = ?
               AND academia_id = ?
            `,
            [
              id,
              academia_id,
            ]
          );

        if (
          Number(
            result?.affectedRows ??
              0
          ) === 0
        ) {
          return reply
            .code(404)
            .send({
              ok: false,
              message:
                "No encontrado",
            });
        }

        return reply.send({
          ok: true,
          deleted: id,
          academia_id,
        });
      } catch (err: any) {
        return reply
          .code(
            getErrorCode(err)
          )
          .send({
            ok: false,

            message:
              "Error al eliminar",

            error:
              err?.message,
          });
      }
    }
  );
}