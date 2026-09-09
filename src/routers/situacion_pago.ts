// src/routers/situacion_pago.ts

import type {
  FastifyInstance,
  FastifyReply,
  FastifyRequest,
} from "fastify";

import { z, ZodError } from "zod";

import { db } from "../db";

import {
  requireAuth,
  requireRoles,
} from "../middlewares/authz";

/**
 * Tabla: situacion_pago
 *
 * Catálogo global del sistema WELI.
 *
 * Campos:
 * - id
 * - nombre
 *
 * Seguridad:
 * - READ: roles 1, 2, 3
 * - WRITE: roles 1, 3
 *
 * Reglas:
 * - situacion_pago NO pertenece directamente a una academia.
 * - situacion_pago NO contiene academia_id.
 * - todos los pagos utilizan este mismo catálogo global.
 * - nombre es único globalmente.
 */

/* =========================================================
   SCHEMAS
========================================================= */

const IdParam = z.object({
  id: z.coerce
    .number()
    .int()
    .positive(),
});

const CreateSchema = z
  .object({
    nombre: z
      .string()
      .trim()
      .min(
        2,
        "Debe tener al menos 2 caracteres"
      )
      .max(
        100,
        "Máximo 100 caracteres"
      ),
  })
  .strict();

const PutSchema = z
  .object({
    nombre: z
      .string()
      .trim()
      .min(
        2,
        "Debe tener al menos 2 caracteres"
      )
      .max(
        100,
        "Máximo 100 caracteres"
      ),
  })
  .strict();

const PatchSchema = z
  .object({
    nombre: z
      .string()
      .trim()
      .min(
        2,
        "Debe tener al menos 2 caracteres"
      )
      .max(
        100,
        "Máximo 100 caracteres"
      )
      .optional(),
  })
  .strict();

/* =========================================================
   HELPERS
========================================================= */

function normalizeName(
  value: string
): string {
  return String(value ?? "")
    .trim()
    .replace(/\s+/g, " ");
}

function normalize(row: any) {
  return {
    id:
      Number(row.id),

    nombre:
      String(row.nombre ?? ""),
  };
}

function zodDetail(
  err: ZodError
): string {
  return err.issues
    .map(
      (issue) =>
        `${
          issue.path.join(".") ||
          "field"
        }: ${issue.message}`
    )
    .join("; ");
}

/* =========================================================
   DUPLICADOS
========================================================= */

async function existsByNombre(
  nombre: string,
  excludeId?: number
): Promise<boolean> {
  const normalized =
    normalizeName(nombre);

  if (!normalized) {
    return false;
  }

  if (
    excludeId !== undefined
  ) {
    const [rows]: any =
      await db.query(
        `
          SELECT id
          FROM situacion_pago

          WHERE LOWER(TRIM(nombre)) =
                LOWER(?)

            AND id <> ?

          LIMIT 1
        `,
        [
          normalized,
          excludeId,
        ]
      );

    return (
      Array.isArray(rows) &&
      rows.length > 0
    );
  }

  const [rows]: any =
    await db.query(
      `
        SELECT id
        FROM situacion_pago

        WHERE LOWER(TRIM(nombre)) =
              LOWER(?)

        LIMIT 1
      `,
      [normalized]
    );

  return (
    Array.isArray(rows) &&
    rows.length > 0
  );
}

/* =========================================================
   ROUTER
========================================================= */

export default async function situacion_pago(
  app: FastifyInstance
) {
  /*
   * Seguridad conservada:
   *
   * READ:
   * - Admin
   * - Staff
   * - Superadmin
   *
   * WRITE:
   * - Admin
   * - Superadmin
   */

  const canRead = [
    requireAuth,
    requireRoles([1, 2, 3]),
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
    async (
      _req: FastifyRequest,
      reply: FastifyReply
    ) => {
      reply.header(
        "Cache-Control",
        "no-store"
      );

      return reply.send({
        module:
          "situacion_pago",

        status:
          "ready",

        scope:
          "global",

        timestamp:
          new Date()
            .toISOString(),
      });
    }
  );

  /* =======================================================
     GET /
     CATÁLOGO GLOBAL
  ======================================================= */

  app.get(
    "/",
    {
      preHandler: canRead,
    },
    async (
      _req: FastifyRequest,
      reply: FastifyReply
    ) => {
      try {
        const [rows]: any =
          await db.query(
            `
              SELECT
                id,
                nombre

              FROM situacion_pago

              ORDER BY
                nombre ASC,
                id ASC
            `
          );

        reply.header(
          "Cache-Control",
          "no-store"
        );

        return reply.send({
          ok: true,

          count:
            rows?.length ?? 0,

          items:
            (rows ?? [])
              .map(normalize),
        });
      } catch (err: any) {
        reply.header(
          "Cache-Control",
          "no-store"
        );

        return reply
          .code(500)
          .send({
            ok: false,

            message:
              "Error al listar situacion_pago",

            detail:
              err?.message,
          });
      }
    }
  );

  /* =======================================================
     GET /:id
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
        reply.header(
          "Cache-Control",
          "no-store"
        );

        return reply
          .code(400)
          .send({
            ok: false,

            message:
              "ID inválido",
          });
      }

      try {
        const id =
          parsed.data.id;

        const [rows]: any =
          await db.query(
            `
              SELECT
                id,
                nombre

              FROM situacion_pago

              WHERE id = ?

              LIMIT 1
            `,
            [id]
          );

        reply.header(
          "Cache-Control",
          "no-store"
        );

        if (!rows?.length) {
          return reply
            .code(404)
            .send({
              ok: false,

              message:
                "Situación de pago no encontrada",
            });
        }

        return reply.send({
          ok: true,

          item:
            normalize(rows[0]),
        });
      } catch (err: any) {
        reply.header(
          "Cache-Control",
          "no-store"
        );

        return reply
          .code(500)
          .send({
            ok: false,

            message:
              "Error al obtener situacion_pago",

            detail:
              err?.message,
          });
      }
    }
  );

  /* =======================================================
     POST /
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
      try {
        const body =
          CreateSchema.parse(
            req.body
          );

        const nombre =
          normalizeName(
            body.nombre
          );

        const duplicate =
          await existsByNombre(
            nombre
          );

        if (duplicate) {
          reply.header(
            "Cache-Control",
            "no-store"
          );

          return reply
            .code(409)
            .send({
              ok: false,

              message:
                "La situación de pago ya existe",
            });
        }

        const [result]: any =
          await db.query(
            `
              INSERT INTO situacion_pago (
                nombre
              )
              VALUES (?)
            `,
            [nombre]
          );

        const insertId =
          Number(
            result?.insertId
          );

        reply.header(
          "Cache-Control",
          "no-store"
        );

        return reply
          .code(201)
          .send({
            ok: true,

            id:
              insertId,

            item: {
              id:
                insertId,

              nombre,
            },
          });
      } catch (err: any) {
        reply.header(
          "Cache-Control",
          "no-store"
        );

        if (
          err instanceof
          ZodError
        ) {
          return reply
            .code(400)
            .send({
              ok: false,

              message:
                "Payload inválido",

              detail:
                zodDetail(err),
            });
        }

        if (
          err?.errno === 1062 ||
          err?.code ===
            "ER_DUP_ENTRY"
        ) {
          return reply
            .code(409)
            .send({
              ok: false,

              message:
                "La situación de pago ya existe",
            });
        }

        return reply
          .code(500)
          .send({
            ok: false,

            message:
              "Error al crear situacion_pago",

            detail:
              err?.message,
          });
      }
    }
  );

  /* =======================================================
     PUT /:id
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
      const parsed =
        IdParam.safeParse(
          req.params
        );

      if (!parsed.success) {
        reply.header(
          "Cache-Control",
          "no-store"
        );

        return reply
          .code(400)
          .send({
            ok: false,

            message:
              "ID inválido",
          });
      }

      try {
        const id =
          parsed.data.id;

        const body =
          PutSchema.parse(
            req.body
          );

        const nombre =
          normalizeName(
            body.nombre
          );

        const duplicate =
          await existsByNombre(
            nombre,
            id
          );

        if (duplicate) {
          reply.header(
            "Cache-Control",
            "no-store"
          );

          return reply
            .code(409)
            .send({
              ok: false,

              message:
                "La situación de pago ya existe",
            });
        }

        const [result]: any =
          await db.query(
            `
              UPDATE situacion_pago

              SET nombre = ?

              WHERE id = ?
            `,
            [
              nombre,
              id,
            ]
          );

        reply.header(
          "Cache-Control",
          "no-store"
        );

        if (
          Number(
            result
              ?.affectedRows ?? 0
          ) === 0
        ) {
          return reply
            .code(404)
            .send({
              ok: false,

              message:
                "Situación de pago no encontrada",
            });
        }

        return reply.send({
          ok: true,

          updated: {
            id,
            nombre,
          },
        });
      } catch (err: any) {
        reply.header(
          "Cache-Control",
          "no-store"
        );

        if (
          err instanceof
          ZodError
        ) {
          return reply
            .code(400)
            .send({
              ok: false,

              message:
                "Payload inválido",

              detail:
                zodDetail(err),
            });
        }

        if (
          err?.errno === 1062 ||
          err?.code ===
            "ER_DUP_ENTRY"
        ) {
          return reply
            .code(409)
            .send({
              ok: false,

              message:
                "La situación de pago ya existe",
            });
        }

        return reply
          .code(500)
          .send({
            ok: false,

            message:
              "Error al actualizar situacion_pago",

            detail:
              err?.message,
          });
      }
    }
  );

  /* =======================================================
     PATCH /:id
  ======================================================= */

  app.patch(
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
        reply.header(
          "Cache-Control",
          "no-store"
        );

        return reply
          .code(400)
          .send({
            ok: false,

            message:
              "ID inválido",
          });
      }

      try {
        const id =
          parsed.data.id;

        const body =
          PatchSchema.parse(
            req.body
          );

        if (
          Object.keys(
            body
          ).length === 0
        ) {
          reply.header(
            "Cache-Control",
            "no-store"
          );

          return reply
            .code(400)
            .send({
              ok: false,

              message:
                "No hay campos para actualizar",
            });
        }

        if (
          body.nombre !==
          undefined
        ) {
          const nombre =
            normalizeName(
              body.nombre
            );

          const duplicate =
            await existsByNombre(
              nombre,
              id
            );

          if (duplicate) {
            reply.header(
              "Cache-Control",
              "no-store"
            );

            return reply
              .code(409)
              .send({
                ok: false,

                message:
                  "La situación de pago ya existe",
              });
          }

          const [result]: any =
            await db.query(
              `
                UPDATE situacion_pago

                SET nombre = ?

                WHERE id = ?
              `,
              [
                nombre,
                id,
              ]
            );

          reply.header(
            "Cache-Control",
            "no-store"
          );

          if (
            Number(
              result
                ?.affectedRows ?? 0
            ) === 0
          ) {
            return reply
              .code(404)
              .send({
                ok: false,

                message:
                  "Situación de pago no encontrada",
              });
          }

          return reply.send({
            ok: true,

            updated: {
              id,
              nombre,
            },
          });
        }

        reply.header(
          "Cache-Control",
          "no-store"
        );

        return reply
          .code(400)
          .send({
            ok: false,

            message:
              "No hay campos válidos para actualizar",
          });
      } catch (err: any) {
        reply.header(
          "Cache-Control",
          "no-store"
        );

        if (
          err instanceof
          ZodError
        ) {
          return reply
            .code(400)
            .send({
              ok: false,

              message:
                "Payload inválido",

              detail:
                zodDetail(err),
            });
        }

        if (
          err?.errno === 1062 ||
          err?.code ===
            "ER_DUP_ENTRY"
        ) {
          return reply
            .code(409)
            .send({
              ok: false,

              message:
                "La situación de pago ya existe",
            });
        }

        return reply
          .code(500)
          .send({
            ok: false,

            message:
              "Error al actualizar situacion_pago",

            detail:
              err?.message,
          });
      }
    }
  );

  /* =======================================================
     DELETE /:id
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
        reply.header(
          "Cache-Control",
          "no-store"
        );

        return reply
          .code(400)
          .send({
            ok: false,

            message:
              "ID inválido",
          });
      }

      try {
        const id =
          parsed.data.id;

        const [result]: any =
          await db.query(
            `
              DELETE FROM situacion_pago

              WHERE id = ?
            `,
            [id]
          );

        reply.header(
          "Cache-Control",
          "no-store"
        );

        if (
          Number(
            result
              ?.affectedRows ?? 0
          ) === 0
        ) {
          return reply
            .code(404)
            .send({
              ok: false,

              message:
                "Situación de pago no encontrada",
            });
        }

        return reply.send({
          ok: true,

          deleted:
            id,
        });
      } catch (err: any) {
        reply.header(
          "Cache-Control",
          "no-store"
        );

        /*
         * pagos_jugador.situacion_pago_id
         * conserva la situación histórica del pago.
         *
         * La FK RESTRICT impide eliminar situaciones
         * que ya estén siendo utilizadas.
         */
        if (
          err?.errno === 1451 ||
          String(
            err?.code ?? ""
          ).includes(
            "ER_ROW_IS_REFERENCED"
          )
        ) {
          return reply
            .code(409)
            .send({
              ok: false,

              message:
                "No se puede eliminar: hay pagos de jugadores vinculados a esta situación de pago.",

              detail:
                err?.sqlMessage ??
                err?.message,
            });
        }

        return reply
          .code(500)
          .send({
            ok: false,

            message:
              "Error al eliminar situacion_pago",

            detail:
              err?.message,
          });
      }
    }
  );
}