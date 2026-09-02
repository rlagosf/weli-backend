// src/routers/tipo_pago.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: tipo_pago
 *
 * Catálogo global del sistema WELI.
 *
 * Campos:
 * - id
 * - nombre
 * - descripcion
 * - estado_id
 *
 * Seguridad:
 * - READ: roles 1 y 3
 * - WRITE: rol 3
 *
 * Reglas:
 * - tipo_pago NO pertenece directamente a una academia.
 * - tipo_pago NO contiene academia_id.
 * - la habilitación de conceptos por academia corresponde a
 *   academia_tipo_pago.
 * - el nombre del tipo de pago es único globalmente.
 */

/* =========================================================
   SCHEMAS
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres").max(100, "Máximo 100 caracteres"),

    descripcion: z.string().trim().max(255, "Máximo 255 caracteres").nullable().optional(),

    estado_id: z.coerce.number().int().positive().default(1),
  })
  .strict();

const PutSchema = z
  .object({
    nombre: z.string().trim().min(3, "El nombre debe tener al menos 3 caracteres").max(100, "Máximo 100 caracteres"),

    descripcion: z.string().trim().max(255, "Máximo 255 caracteres").nullable(),

    estado_id: z.coerce.number().int().positive(),
  })
  .strict();

const PatchSchema = z
  .object({
    nombre: z
      .string()
      .trim()
      .min(3, "El nombre debe tener al menos 3 caracteres")
      .max(100, "Máximo 100 caracteres")
      .optional(),

    descripcion: z.string().trim().max(255, "Máximo 255 caracteres").nullable().optional(),

    estado_id: z.coerce.number().int().positive().optional(),
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

function normalizeDescription(value: unknown): string | null {
  if (value == null) {
    return null;
  }

  const normalized = String(value).trim().replace(/\s+/g, " ");

  return normalized || null;
}

function normalize(row: any) {
  return {
    id: Number(row.id),
    nombre: String(row.nombre ?? ""),
    descripcion: row.descripcion == null ? null : String(row.descripcion),
    estado_id: Number(row.estado_id),
  };
}

function zodDetail(err: ZodError) {
  return err.issues.map((issue) => `${issue.path.join(".") || "field"}: ${issue.message}`).join("; ");
}

async function existsByNombre(nombre: string, excludeId?: number): Promise<boolean> {
  const normalized = normalizeName(nombre);

  if (!normalized) {
    return false;
  }

  if (excludeId !== undefined) {
    const [rows]: any = await db.query(
      `
        SELECT id
        FROM tipo_pago
        WHERE LOWER(TRIM(nombre)) = LOWER(?)
          AND id <> ?
        LIMIT 1
      `,
      [normalized, excludeId]
    );

    return Array.isArray(rows) && rows.length > 0;
  }

  const [rows]: any = await db.query(
    `
      SELECT id
      FROM tipo_pago
      WHERE LOWER(TRIM(nombre)) = LOWER(?)
      LIMIT 1
    `,
    [normalized]
  );

  return Array.isArray(rows) && rows.length > 0;
}

function handleDatabaseError(reply: FastifyReply, err: any, operation: string) {
  reply.header("Cache-Control", "no-store");

  if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
    return reply.code(409).send({
      ok: false,
      message: "Ya existe un tipo de pago con ese nombre",
    });
  }

  if (
    err?.errno === 1451 ||
    err?.code === "ER_ROW_IS_REFERENCED_2" ||
    String(err?.code ?? "").includes("ER_ROW_IS_REFERENCED")
  ) {
    return reply.code(409).send({
      ok: false,
      message: "No se puede eliminar el tipo de pago porque existen registros asociados",
    });
  }

  return reply.code(500).send({
    ok: false,
    message: `Error al ${operation} tipo de pago`,
  });
}

/* =========================================================
   ROUTER
========================================================= */

export default async function tipo_pago(app: FastifyInstance) {
  /*
   * Admin:
   * - lectura del catálogo.
   *
   * Superadmin:
   * - lectura y administración del catálogo.
   *
   * Staff:
   * - sin acceso.
   */
  const canRead = [requireAuth, requireRoles([1, 3])];

  const onlySuper = [requireAuth, requireRoles([3])];

  /* =======================================================
     HEALTH
  ======================================================= */

  app.get(
    "/health",
    {
      preHandler: canRead,
    },
    async (_req: FastifyRequest, reply: FastifyReply) => {
      reply.header("Cache-Control", "no-store");

      return reply.send({
        module: "tipo_pago",
        status: "ready",
        scope: "global",
        timestamp: new Date().toISOString(),
      });
    }
  );

  /* =======================================================
     GET /
     Catálogo global
  ======================================================= */

  app.get(
    "/",
    {
      preHandler: canRead,
    },
    async (_req: FastifyRequest, reply: FastifyReply) => {
      try {
        const [rows]: any = await db.query(
          `
              SELECT
                id,
                nombre,
                descripcion,
                estado_id
              FROM tipo_pago
              ORDER BY
                nombre ASC,
                id ASC
            `
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,
          count: rows?.length ?? 0,
          items: (rows ?? []).map(normalize),
        });
      } catch (err: any) {
        return handleDatabaseError(reply, err, "listar");
      }
    }
  );

  /* =======================================================
     GET /:id
     Tipo global específico
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
        const id = parsed.data.id;

        const [rows]: any = await db.query(
          `
              SELECT
                id,
                nombre,
                descripcion,
                estado_id
              FROM tipo_pago
              WHERE id = ?
              LIMIT 1
            `,
          [id]
        );

        reply.header("Cache-Control", "no-store");

        if (!rows?.length) {
          return reply.code(404).send({
            ok: false,
            message: "Tipo de pago no encontrado",
          });
        }

        return reply.send({
          ok: true,
          item: normalize(rows[0]),
        });
      } catch (err: any) {
        return handleDatabaseError(reply, err, "obtener");
      }
    }
  );

  /* =======================================================
     POST /
     Crear concepto global
  ======================================================= */

  app.post(
    "/",
    {
      preHandler: onlySuper,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const body = CreateSchema.parse(req.body);

        const nombre = normalizeName(body.nombre);

        const descripcion = normalizeDescription(body.descripcion);

        const estadoId = Number(body.estado_id);

        const duplicate = await existsByNombre(nombre);

        if (duplicate) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,
            message: "Ya existe un tipo de pago con ese nombre",
          });
        }

        const [result]: any = await db.query(
          `
              INSERT INTO tipo_pago (
                nombre,
                descripcion,
                estado_id
              )
              VALUES (?, ?, ?)
            `,
          [nombre, descripcion, estadoId]
        );

        const insertId = Number(result?.insertId);

        const [rows]: any = await db.query(
          `
              SELECT
                id,
                nombre,
                descripcion,
                estado_id
              FROM tipo_pago
              WHERE id = ?
              LIMIT 1
            `,
          [insertId]
        );

        reply.header("Cache-Control", "no-store");

        return reply.code(201).send({
          ok: true,
          id: insertId,
          item: rows?.length
            ? normalize(rows[0])
            : {
                id: insertId,
                nombre,
                descripcion,
                estado_id: estadoId,
              },
        });
      } catch (err: any) {
        reply.header("Cache-Control", "no-store");

        if (err instanceof ZodError) {
          return reply.code(400).send({
            ok: false,
            message: "Datos inválidos",
            detail: zodDetail(err),
          });
        }

        return handleDatabaseError(reply, err, "crear");
      }
    }
  );

  /* =======================================================
     PUT /:id
     Reemplazo completo
  ======================================================= */

  app.put(
    "/:id",
    {
      preHandler: onlySuper,
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
        const id = parsed.data.id;

        const body = PutSchema.parse(req.body);

        const nombre = normalizeName(body.nombre);

        const descripcion = normalizeDescription(body.descripcion);

        const estadoId = Number(body.estado_id);

        const duplicate = await existsByNombre(nombre, id);

        if (duplicate) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,
            message: "Ya existe un tipo de pago con ese nombre",
          });
        }

        const [result]: any = await db.query(
          `
              UPDATE tipo_pago
              SET
                nombre = ?,
                descripcion = ?,
                estado_id = ?
              WHERE id = ?
            `,
          [nombre, descripcion, estadoId, id]
        );

        reply.header("Cache-Control", "no-store");

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,
            message: "Tipo de pago no encontrado",
          });
        }

        const [rows]: any = await db.query(
          `
              SELECT
                id,
                nombre,
                descripcion,
                estado_id
              FROM tipo_pago
              WHERE id = ?
              LIMIT 1
            `,
          [id]
        );

        return reply.send({
          ok: true,
          updated: rows?.length
            ? normalize(rows[0])
            : {
                id,
                nombre,
                descripcion,
                estado_id: estadoId,
              },
        });
      } catch (err: any) {
        reply.header("Cache-Control", "no-store");

        if (err instanceof ZodError) {
          return reply.code(400).send({
            ok: false,
            message: "Datos inválidos",
            detail: zodDetail(err),
          });
        }

        return handleDatabaseError(reply, err, "actualizar");
      }
    }
  );

  /* =======================================================
     PATCH /:id
     Actualización parcial
  ======================================================= */

  app.patch(
    "/:id",
    {
      preHandler: onlySuper,
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
        const id = parsed.data.id;

        const body = PatchSchema.parse(req.body);

        if (Object.keys(body).length === 0) {
          reply.header("Cache-Control", "no-store");

          return reply.code(400).send({
            ok: false,
            message: "No hay campos para actualizar",
          });
        }

        const [currentRows]: any = await db.query(
          `
              SELECT
                id,
                nombre,
                descripcion,
                estado_id
              FROM tipo_pago
              WHERE id = ?
              LIMIT 1
            `,
          [id]
        );

        if (!currentRows?.length) {
          reply.header("Cache-Control", "no-store");

          return reply.code(404).send({
            ok: false,
            message: "Tipo de pago no encontrado",
          });
        }

        const current = currentRows[0];

        const nombre = body.nombre !== undefined ? normalizeName(body.nombre) : String(current.nombre);

        const descripcion =
          body.descripcion !== undefined
            ? normalizeDescription(body.descripcion)
            : normalizeDescription(current.descripcion);

        const estadoId = body.estado_id !== undefined ? Number(body.estado_id) : Number(current.estado_id);

        if (body.nombre !== undefined) {
          const duplicate = await existsByNombre(nombre, id);

          if (duplicate) {
            reply.header("Cache-Control", "no-store");

            return reply.code(409).send({
              ok: false,
              message: "Ya existe un tipo de pago con ese nombre",
            });
          }
        }

        await db.query(
          `
            UPDATE tipo_pago
            SET
              nombre = ?,
              descripcion = ?,
              estado_id = ?
            WHERE id = ?
          `,
          [nombre, descripcion, estadoId, id]
        );

        const [rows]: any = await db.query(
          `
              SELECT
                id,
                nombre,
                descripcion,
                estado_id
              FROM tipo_pago
              WHERE id = ?
              LIMIT 1
            `,
          [id]
        );

        reply.header("Cache-Control", "no-store");

        return reply.send({
          ok: true,
          updated: rows?.length
            ? normalize(rows[0])
            : {
                id,
                nombre,
                descripcion,
                estado_id: estadoId,
              },
        });
      } catch (err: any) {
        reply.header("Cache-Control", "no-store");

        if (err instanceof ZodError) {
          return reply.code(400).send({
            ok: false,
            message: "Datos inválidos",
            detail: zodDetail(err),
          });
        }

        return handleDatabaseError(reply, err, "actualizar");
      }
    }
  );

  /* =======================================================
     DELETE /:id
     Eliminación del catálogo global
  ======================================================= */

  app.delete(
    "/:id",
    {
      preHandler: onlySuper,
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
        const id = parsed.data.id;

        const [result]: any = await db.query(
          `
              DELETE FROM tipo_pago
              WHERE id = ?
            `,
          [id]
        );

        reply.header("Cache-Control", "no-store");

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,
            message: "Tipo de pago no encontrado",
          });
        }

        return reply.send({
          ok: true,
          deleted: id,
        });
      } catch (err: any) {
        reply.header("Cache-Control", "no-store");

        if (
          err?.errno === 1451 ||
          err?.code === "ER_ROW_IS_REFERENCED_2" ||
          String(err?.code ?? "").includes("ER_ROW_IS_REFERENCED")
        ) {
          return reply.code(409).send({
            ok: false,
            message:
              "No se puede eliminar el tipo de pago porque está asociado a academias, tarifas, promociones, cargos u otros registros",
          });
        }

        return handleDatabaseError(reply, err, "eliminar");
      }
    }
  );
}
