// src/routers/medio_pago.ts

import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";

import { z, ZodError } from "zod";

import { db } from "../db";

import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: medio_pago
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
 * - medio_pago NO pertenece directamente a una academia.
 * - medio_pago NO contiene academia_id.
 * - todos los pagos utilizan este mismo catálogo global.
 * - nombre es único globalmente.
 */

/* =========================================================
   SCHEMAS
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const CreateSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(50, "Máximo 50 caracteres"),
  })
  .strict();

/*
 * PUT = reemplazo completo.
 * nombre requerido.
 */
const PutSchema = z
  .object({
    nombre: z.string().trim().min(2, "Debe tener al menos 2 caracteres").max(50, "Máximo 50 caracteres"),
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

function normalize(row: any) {
  return {
    id: Number(row.id),

    nombre: String(row.nombre ?? ""),
  };
}

function zodDetail(err: ZodError): string {
  return err.issues.map((issue) => `${issue.path.join(".") || "field"}: ${issue.message}`).join("; ");
}

/* =========================================================
   DUPLICADOS
========================================================= */

async function existsByNombre(nombre: string, excludeId?: number): Promise<boolean> {
  const normalized = normalizeName(nombre);

  if (!normalized) {
    return false;
  }

  if (excludeId !== undefined) {
    const [rows]: any = await db.query(
      `
          SELECT id
          FROM medio_pago

          WHERE LOWER(TRIM(nombre)) =
                LOWER(?)

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
        FROM medio_pago

        WHERE LOWER(TRIM(nombre)) =
              LOWER(?)

        LIMIT 1
      `,
    [normalized]
  );

  return Array.isArray(rows) && rows.length > 0;
}

/* =========================================================
   ROUTER
========================================================= */

export default async function medio_pago(app: FastifyInstance) {
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
    async (_req: FastifyRequest, reply: FastifyReply) => {
      reply.header("Cache-Control", "no-store");

      return reply.send({
        module: "medio_pago",
        status: "ready",
        scope: "global",
        timestamp: new Date().toISOString(),
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
    async (_req: FastifyRequest, reply: FastifyReply) => {
      try {
        const [rows]: any = await db.query(
          `
              SELECT
                id,
                nombre

              FROM medio_pago

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
        reply.header("Cache-Control", "no-store");

        return reply.code(500).send({
          ok: false,

          message: "Error al listar medio_pago",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     GET /:id
     MEDIO DE PAGO GLOBAL ESPECÍFICO
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
                nombre

              FROM medio_pago

              WHERE id = ?

              LIMIT 1
            `,
          [id]
        );

        reply.header("Cache-Control", "no-store");

        if (!rows?.length) {
          return reply.code(404).send({
            ok: false,

            message: "Medio de pago no encontrado",
          });
        }

        return reply.send({
          ok: true,

          item: normalize(rows[0]),
        });
      } catch (err: any) {
        reply.header("Cache-Control", "no-store");

        return reply.code(500).send({
          ok: false,

          message: "Error al obtener medio_pago",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     POST /
     CREAR MEDIO DE PAGO GLOBAL
  ======================================================= */

  app.post(
    "/",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      try {
        const body = CreateSchema.parse(req.body);

        const nombre = normalizeName(body.nombre);

        const duplicate = await existsByNombre(nombre);

        if (duplicate) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "El medio de pago ya existe",
          });
        }

        const [result]: any = await db.query(
          `
              INSERT INTO medio_pago (
                nombre
              )
              VALUES (?)
            `,
          [nombre]
        );

        const insertId = Number(result?.insertId);

        reply.header("Cache-Control", "no-store");

        return reply.code(201).send({
          ok: true,

          id: insertId,

          item: {
            id: insertId,

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

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "El medio de pago ya existe",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al crear medio_pago",

          detail: err?.message,
        });
      }
    }
  );

  /* =======================================================
     PUT /:id
     ACTUALIZAR MEDIO DE PAGO GLOBAL
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
        const id = parsed.data.id;

        const body = PutSchema.parse(req.body);

        const nombre = normalizeName(body.nombre);

        const duplicate = await existsByNombre(nombre, id);

        if (duplicate) {
          reply.header("Cache-Control", "no-store");

          return reply.code(409).send({
            ok: false,

            message: "El medio de pago ya existe",
          });
        }

        const [result]: any = await db.query(
          `
              UPDATE medio_pago

              SET nombre = ?

              WHERE id = ?
            `,
          [nombre, id]
        );

        reply.header("Cache-Control", "no-store");

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,

            message: "Medio de pago no encontrado",
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
        reply.header("Cache-Control", "no-store");

        if (err instanceof ZodError) {
          return reply.code(400).send({
            ok: false,

            message: "Payload inválido",

            detail: zodDetail(err),
          });
        }

        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "El medio de pago ya existe",
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al actualizar medio_pago",

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
        const id = parsed.data.id;

        const [result]: any = await db.query(
          `
              DELETE FROM medio_pago

              WHERE id = ?
            `,
          [id]
        );

        reply.header("Cache-Control", "no-store");

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,

            message: "Medio de pago no encontrado",
          });
        }

        return reply.send({
          ok: true,

          deleted: id,
        });
      } catch (err: any) {
        reply.header("Cache-Control", "no-store");

        /*
         * pagos_jugador.medio_pago_id mantiene
         * la referencia histórica al catálogo.
         *
         * La FK impide eliminar medios de pago
         * que ya fueron utilizados.
         */
        if (err?.errno === 1451 || String(err?.code ?? "").includes("ER_ROW_IS_REFERENCED")) {
          return reply.code(409).send({
            ok: false,

            message: "No se puede eliminar: el medio de pago está siendo utilizado por pagos registrados",

            detail: err?.sqlMessage ?? err?.message,
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al eliminar medio_pago",

          detail: err?.message,
        });
      }
    }
  );
}
