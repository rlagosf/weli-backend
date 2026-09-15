// src/routers/categorias.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z, ZodError } from "zod";

import { db } from "../db";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * =========================================================
 * WELI - CATEGORÍAS POR ACADEMIA
 * =========================================================
 *
 * Tabla:
 *
 * categorias
 *
 * Campos:
 *
 * - id
 * - academia_id
 * - nombre
 *
 * Modelo:
 *
 * Las categorías NO constituyen un catálogo global.
 *
 * Cada academia define sus propias categorías:
 *
 * Academia A:
 * - Sub 8
 * - Sub 10
 * - Sub 12
 *
 * Academia B:
 * - Infantil
 * - Juvenil
 * - Adulto
 *
 * Seguridad:
 *
 * READ:
 * - Admin       rol 1
 * - Staff       rol 2
 * - Superadmin  rol 3
 *
 * WRITE:
 * - Admin       rol 1
 * - Superadmin  rol 3
 *
 * Scope:
 *
 * Admin / Staff:
 * - academia_id proviene del JWT firmado.
 *
 * Superadmin:
 * - academia_id proviene de x-academia-id.
 *
 * academia_id NUNCA se recibe desde el body.
 *
 * Reglas:
 *
 * - nombre máximo 50 caracteres,
 *   de acuerdo con VARCHAR(50).
 *
 * - nombre es único dentro de una academia.
 *
 * - distintas academias sí pueden utilizar
 *   el mismo nombre de categoría.
 *
 * - una categoría utilizada por jugadores
 *   no puede eliminarse debido a FK RESTRICT.
 * =========================================================
 */

/* =========================================================
   CONSTANTES
========================================================= */

const MAX_NOMBRE_CATEGORIA = 50;

/* =========================================================
   SCHEMAS
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const NombreCategoriaSchema = z
  .string()
  .trim()
  .min(1, "nombre requerido")
  .max(MAX_NOMBRE_CATEGORIA, `El nombre no puede superar ${MAX_NOMBRE_CATEGORIA} caracteres`);

const CreateSchema = z
  .object({
    nombre: NombreCategoriaSchema,
  })
  .strict();

const PutSchema = z
  .object({
    nombre: NombreCategoriaSchema,
  })
  .strict();

const PatchSchema = z
  .object({
    nombre: NombreCategoriaSchema.optional(),
  })
  .strict();

/* =========================================================
   HELPERS
========================================================= */

function normalizeName(value: string): string {
  return String(value ?? "")
    .trim()
    .replace(/\s+/g, " ");
}

function comparableName(value: string): string {
  return normalizeName(value).toLocaleLowerCase("es");
}

function normalize(row: any) {
  return {
    id: Number(row.id),

    academia_id: Number(row.academia_id),

    nombre: String(row.nombre ?? ""),
  };
}

function zodDetail(err: ZodError): string {
  return err.issues.map((issue) => `${issue.path.join(".") || "field"}: ${issue.message}`).join("; ");
}

function businessError(message: string, statusCode = 400): never {
  const err: any = new Error(message);

  err.statusCode = statusCode;

  throw err;
}

/* =========================================================
   ACADEMIA EFECTIVA
========================================================= */

function resolveAcademiaId(req: FastifyRequest): number {
  const academiaId = Number(getEffectiveAcademiaId(req));

  if (!Number.isInteger(academiaId) || academiaId <= 0) {
    businessError("Academia efectiva inválida", 403);
  }

  return academiaId;
}

/* =========================================================
   OBTENER CATEGORÍA
========================================================= */

async function getCategoria(academiaId: number, id: number, executor: any = db) {
  const [rows]: any = await executor.query(
    `
        SELECT
          id,
          academia_id,
          nombre

        FROM categorias

        WHERE id = ?
          AND academia_id = ?

        LIMIT 1
      `,
    [id, academiaId]
  );

  return rows?.length ? rows[0] : null;
}

/* =========================================================
   DUPLICADOS
========================================================= */

async function existsByNombreScoped(
  academiaId: number,
  nombre: string,
  excludeId?: number,
  executor: any = db
): Promise<boolean> {
  const normalized = comparableName(nombre);

  if (!normalized) {
    return false;
  }

  const values: any[] = [academiaId, normalized];

  let sql = `
    SELECT
      id

    FROM categorias

    WHERE academia_id = ?

      AND LOWER(
            TRIM(nombre)
          ) = ?
  `;

  if (excludeId !== undefined) {
    sql += `
      AND id <> ?
    `;

    values.push(excludeId);
  }

  sql += `
    LIMIT 1
  `;

  const [rows]: any = await executor.query(sql, values);

  return Array.isArray(rows) && rows.length > 0;
}

/* =========================================================
   ERRORES
========================================================= */

function handleKnownError(reply: FastifyReply, err: any) {
  reply.header("Cache-Control", "no-store");

  const status = Number(err?.statusCode ?? 0);

  if ([400, 401, 403, 404, 409].includes(status)) {
    return reply.code(status).send({
      ok: false,

      message: err?.message ?? "No fue posible procesar la solicitud",
    });
  }

  return null;
}

/* =========================================================
   ROUTER
========================================================= */

export default async function categorias(app: FastifyInstance) {
  /*
   * Staff puede consultar categorías
   * para su operación diaria.
   *
   * Solo Admin y Superadmin
   * pueden administrarlas.
   */
  const canRead = [requireAuth, requireRoles([1, 2, 3])];

  const canWrite = [requireAuth, requireRoles([1, 3])];

  /* =======================================================
     HEALTH
  ======================================================= */

  app.get(
    "/health",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const academiaId = resolveAcademiaId(req);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          module: "categorias",

          status: "ready",

          academia_id: academiaId,

          timestamp: new Date().toISOString(),
        });
      } catch (err: any) {
        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        return reply.code(500).send({
          ok: false,

          message: "Error en módulo categorias",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     GET /
  ======================================================= */

  app.get(
    "/",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const academiaId = resolveAcademiaId(req);

        const [rows]: any = await db.query(
          `
              SELECT
                id,
                academia_id,
                nombre

              FROM categorias

              WHERE academia_id = ?

              ORDER BY
                nombre ASC,
                id ASC
            `,
          [academiaId]
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          academia_id: academiaId,

          count: rows?.length ?? 0,

          items: (rows ?? []).map(normalize),
        });
      } catch (err: any) {
        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        reply.header("Cache-Control", "no-store");

        return reply.code(500).send({
          ok: false,

          message: "Error al consultar categorías",

          detail: err?.message,
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
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse(req.params);

      if (!parsed.success) {
        reply.header("Cache-Control", "no-store");

        return reply.code(400).send({
          ok: false,

          message: "ID inválido",
        });
      }

      try {
        const academiaId = resolveAcademiaId(req);

        const row = await getCategoria(academiaId, parsed.data.id);

        reply.header("Cache-Control", "no-store");

        if (!row) {
          return reply.code(404).send({
            ok: false,

            message: "Categoría no encontrada",
          });
        }

        return reply.send({
          ok: true,

          academia_id: academiaId,

          item: normalize(row),
        });
      } catch (err: any) {
        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        reply.header("Cache-Control", "no-store");

        return reply.code(500).send({
          ok: false,

          message: "Error al buscar categoría",

          detail: err?.message,
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
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const body = CreateSchema.parse(req.body);

        const academiaId = resolveAcademiaId(req);

        const nombre = normalizeName(body.nombre);

        const duplicate = await existsByNombreScoped(academiaId, nombre);

        if (duplicate) {
          businessError("La categoría ya existe en esta academia", 409);
        }

        const [result]: any = await db.query(
          `
              INSERT INTO categorias (
                academia_id,
                nombre
              )

              VALUES (?, ?)
            `,
          [academiaId, nombre]
        );

        const insertId = Number(result?.insertId);

        if (!Number.isInteger(insertId) || insertId <= 0) {
          throw new Error("No fue posible obtener el ID de la categoría creada");
        }

        const row = await getCategoria(academiaId, insertId);

        reply.header("Cache-Control", "no-store");

        return reply.code(201).send({
          ok: true,

          id: insertId,

          item: row
            ? normalize(row)
            : {
                id: insertId,

                academia_id: academiaId,

                nombre,
              },
        });
      } catch (err: any) {
        reply.header("Cache-Control", "no-store");

        if (err instanceof ZodError) {
          return reply.code(400).send({
            ok: false,

            message: "Payload inválido",

            detail: zodDetail(err),
          });
        }

        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "La categoría ya existe en esta academia",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al crear categoría",

          detail: err?.message,
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
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse(req.params);

      if (!parsed.success) {
        reply.header("Cache-Control", "no-store");

        return reply.code(400).send({
          ok: false,

          message: "ID inválido",
        });
      }

      try {
        const academiaId = resolveAcademiaId(req);

        const id = parsed.data.id;

        const current = await getCategoria(academiaId, id);

        if (!current) {
          businessError("Categoría no encontrada", 404);
        }

        const body = PutSchema.parse(req.body);

        const nombre = normalizeName(body.nombre);

        const duplicate = await existsByNombreScoped(academiaId, nombre, id);

        if (duplicate) {
          businessError("La categoría ya existe en esta academia", 409);
        }

        const [result]: any = await db.query(
          `
              UPDATE categorias

              SET
                nombre = ?

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [nombre, id, academiaId]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          businessError("Categoría no encontrada", 404);
        }

        const updated = await getCategoria(academiaId, id);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          updated: updated
            ? normalize(updated)
            : {
                id,

                academia_id: academiaId,

                nombre,
              },
        });
      } catch (err: any) {
        reply.header("Cache-Control", "no-store");

        if (err instanceof ZodError) {
          return reply.code(400).send({
            ok: false,

            message: "Payload inválido",

            detail: zodDetail(err),
          });
        }

        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "La categoría ya existe en esta academia",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al actualizar categoría",

          detail: err?.message,
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
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse(req.params);

      if (!parsed.success) {
        reply.header("Cache-Control", "no-store");

        return reply.code(400).send({
          ok: false,

          message: "ID inválido",
        });
      }

      try {
        const academiaId = resolveAcademiaId(req);

        const id = parsed.data.id;

        const body = PatchSchema.parse(req.body);

        if (Object.keys(body).length === 0) {
          businessError("No hay campos para actualizar");
        }

        const current = await getCategoria(academiaId, id);

        if (!current) {
          businessError("Categoría no encontrada", 404);
        }

        const nombre = body.nombre !== undefined ? normalizeName(body.nombre) : String(current.nombre);

        const duplicate = await existsByNombreScoped(academiaId, nombre, id);

        if (duplicate) {
          businessError("La categoría ya existe en esta academia", 409);
        }

        const [result]: any = await db.query(
          `
              UPDATE categorias

              SET
                nombre = ?

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [nombre, id, academiaId]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          businessError("Categoría no encontrada", 404);
        }

        const updated = await getCategoria(academiaId, id);

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          updated: updated
            ? normalize(updated)
            : {
                id,

                academia_id: academiaId,

                nombre,
              },
        });
      } catch (err: any) {
        reply.header("Cache-Control", "no-store");

        if (err instanceof ZodError) {
          return reply.code(400).send({
            ok: false,

            message: "Payload inválido",

            detail: zodDetail(err),
          });
        }

        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "La categoría ya existe en esta academia",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al actualizar categoría",

          detail: err?.message,
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
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = IdParam.safeParse(req.params);

      if (!parsed.success) {
        reply.header("Cache-Control", "no-store");

        return reply.code(400).send({
          ok: false,

          message: "ID inválido",
        });
      }

      try {
        const academiaId = resolveAcademiaId(req);

        const id = parsed.data.id;

        const current = await getCategoria(academiaId, id);

        if (!current) {
          businessError("Categoría no encontrada", 404);
        }

        const [result]: any = await db.query(
          `
              DELETE
              FROM categorias

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [id, academiaId]
        );

        if (Number(result?.affectedRows ?? 0) === 0) {
          businessError("Categoría no encontrada", 404);
        }

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,

          academia_id: academiaId,

          deleted: id,
        });
      } catch (err: any) {
        reply.header("Cache-Control", "no-store");

        const handled = handleKnownError(reply, err);

        if (handled) {
          return handled;
        }

        if (
          err?.errno === 1451 ||
          err?.code === "ER_ROW_IS_REFERENCED_2" ||
          String(err?.code ?? "").includes("ER_ROW_IS_REFERENCED")
        ) {
          return reply.code(409).send({
            ok: false,

            message:
              "No se puede eliminar la categoría porque está siendo utilizada por jugadores u otra información relacionada",

            detail: err?.sqlMessage ?? err?.message,
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al eliminar categoría",

          detail: err?.message,
        });
      }
    }
  );
}
