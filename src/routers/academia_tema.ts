import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/**
 * =========================================================
 * WELI - TEMA DE ACADEMIA
 * =========================================================
 *
 * Responsabilidad:
 * - Leer la apariencia efectiva de una academia.
 * - Guardar / actualizar su personalización visual.
 * - Restaurar el tema WELI eliminando la personalización.
 *
 * Seguridad:
 *
 * Admin:
 * - lee y administra solamente su academia efectiva.
 *
 * Staff:
 * - solamente puede leer el tema de su academia efectiva.
 *
 * Superadmin:
 * - lee y administra la academia seleccionada mediante
 *   el scope efectivo de getEffectiveAcademiaId(req).
 *
 * Nunca se acepta academia_id desde el body como autoridad.
 * =========================================================
 */

const DEFAULT_THEME = {
  color_fondo: "#F5E8D0",
  color_tarjeta: "#FFFFFF",
  color_primario: "#AA5013",
  color_secundario: "#6D5829",
  color_texto: "#3B2A1E",
  color_icono: "#AA5013",
} as const;

const HexColorSchema = z
  .string()
  .trim()
  .regex(/^#[0-9A-Fa-f]{6}$/, "El color debe tener formato hexadecimal #RRGGBB")
  .transform((value) => value.toUpperCase());

const ThemeWriteSchema = z
  .object({
    color_fondo: HexColorSchema,
    color_tarjeta: HexColorSchema,
    color_primario: HexColorSchema,
    color_secundario: HexColorSchema,
    color_texto: HexColorSchema,
    color_icono: HexColorSchema,
  })
  .strict();

function resolveAcademiaId(req: FastifyRequest): number {
  const academiaId = Number(getEffectiveAcademiaId(req));

  if (!Number.isInteger(academiaId) || academiaId <= 0) {
    const error: any = new Error("Academia efectiva inválida");
    error.statusCode = 403;
    throw error;
  }

  return academiaId;
}

function mysqlError(error: any): {
  status: number;
  message: string;
} {
  if (error instanceof z.ZodError) {
    const first = error.issues?.[0];

    return {
      status: 400,
      message: first?.message ?? "Datos inválidos",
    };
  }

  if (error?.code === "ER_NO_REFERENCED_ROW_2") {
    return {
      status: 400,
      message: "La academia relacionada no existe o no es válida",
    };
  }

  if (error?.code === "ER_DUP_ENTRY") {
    return {
      status: 409,
      message: "La academia ya posee una configuración visual",
    };
  }

  const status = Number(error?.statusCode ?? 400);

  return {
    status: Number.isInteger(status) && status >= 400 && status <= 599 ? status : 400,
    message: error?.message ?? "BAD_REQUEST",
  };
}

async function ensureAcademiaExists(academiaId: number): Promise<void> {
  const [rows]: any = await db.query(
    `
      SELECT id
      FROM academias
      WHERE id = ?
      LIMIT 1
    `,
    [academiaId]
  );

  if (!rows?.length) {
    const error: any = new Error("Academia no encontrada");
    error.statusCode = 404;
    throw error;
  }
}

function themeFromRow(row: any) {
  return {
    color_fondo: String(row?.color_fondo ?? DEFAULT_THEME.color_fondo).toUpperCase(),
    color_tarjeta: String(row?.color_tarjeta ?? DEFAULT_THEME.color_tarjeta).toUpperCase(),
    color_primario: String(row?.color_primario ?? DEFAULT_THEME.color_primario).toUpperCase(),
    color_secundario: String(row?.color_secundario ?? DEFAULT_THEME.color_secundario).toUpperCase(),
    color_texto: String(row?.color_texto ?? DEFAULT_THEME.color_texto).toUpperCase(),
    color_icono: String(row?.color_icono ?? DEFAULT_THEME.color_icono).toUpperCase(),
  };
}

export default async function academiaTema(app: FastifyInstance) {
  const canRead = [requireAuth, requireRoles([1, 2, 3])];
  const canManage = [requireAuth, requireRoles([1, 3])];
  const onlySuper = [requireAuth, requireRoles([3])];

  app.get(
    "/health",
    {
      preHandler: onlySuper,
    },
    async () => ({
      module: "academia_tema",
      status: "ready",
      timestamp: new Date().toISOString(),
    })
  );

  app.get(
    "/",
    {
      preHandler: canRead,
    },
    async (req, reply) => {
      try {
        const academiaId = resolveAcademiaId(req);

        await ensureAcademiaExists(academiaId);

        const [rows]: any = await db.query(
          `
            SELECT
              id,
              academia_id,
              color_fondo,
              color_tarjeta,
              color_primario,
              color_secundario,
              color_texto,
              color_icono,
              created_at,
              updated_at
            FROM academia_tema
            WHERE academia_id = ?
            LIMIT 1
          `,
          [academiaId]
        );

        const row = rows?.[0] ?? null;

        return reply.send({
          ok: true,
          academia_id: academiaId,
          personalizado: Boolean(row),
          tema: row ? themeFromRow(row) : { ...DEFAULT_THEME },
          created_at: row?.created_at ?? null,
          updated_at: row?.updated_at ?? null,
        });
      } catch (error: any) {
        const parsed = mysqlError(error);

        return reply.code(parsed.status).send({
          ok: false,
          message: parsed.message,
        });
      }
    }
  );

  app.put(
    "/",
    {
      preHandler: canManage,
    },
    async (req, reply) => {
      try {
        const academiaId = resolveAcademiaId(req);
        const body = ThemeWriteSchema.parse(req.body);

        await ensureAcademiaExists(academiaId);

        await db.query(
          `
            INSERT INTO academia_tema (
              academia_id,
              color_fondo,
              color_tarjeta,
              color_primario,
              color_secundario,
              color_texto,
              color_icono
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)

            ON DUPLICATE KEY UPDATE
              color_fondo = VALUES(color_fondo),
              color_tarjeta = VALUES(color_tarjeta),
              color_primario = VALUES(color_primario),
              color_secundario = VALUES(color_secundario),
              color_texto = VALUES(color_texto),
              color_icono = VALUES(color_icono),
              updated_at = CURRENT_TIMESTAMP
          `,
          [
            academiaId,
            body.color_fondo,
            body.color_tarjeta,
            body.color_primario,
            body.color_secundario,
            body.color_texto,
            body.color_icono,
          ]
        );

        const [rows]: any = await db.query(
          `
            SELECT
              id,
              academia_id,
              color_fondo,
              color_tarjeta,
              color_primario,
              color_secundario,
              color_texto,
              color_icono,
              created_at,
              updated_at
            FROM academia_tema
            WHERE academia_id = ?
            LIMIT 1
          `,
          [academiaId]
        );

        const row = rows?.[0] ?? null;

        return reply.send({
          ok: true,
          academia_id: academiaId,
          personalizado: true,
          tema: row ? themeFromRow(row) : themeFromRow(body),
          created_at: row?.created_at ?? null,
          updated_at: row?.updated_at ?? null,
          message: "Tema de la academia actualizado correctamente",
        });
      } catch (error: any) {
        const parsed = mysqlError(error);

        return reply.code(parsed.status).send({
          ok: false,
          message: parsed.message,
        });
      }
    }
  );

  app.delete(
    "/",
    {
      preHandler: canManage,
    },
    async (req, reply) => {
      try {
        const academiaId = resolveAcademiaId(req);

        await ensureAcademiaExists(academiaId);

        await db.query(
          `
            DELETE
            FROM academia_tema
            WHERE academia_id = ?
          `,
          [academiaId]
        );

        return reply.send({
          ok: true,
          academia_id: academiaId,
          personalizado: false,
          tema: { ...DEFAULT_THEME },
          created_at: null,
          updated_at: null,
          message: "Tema WELI restaurado correctamente",
        });
      } catch (error: any) {
        const parsed = mysqlError(error);

        return reply.code(parsed.status).send({
          ok: false,
          message: parsed.message,
        });
      }
    }
  );
}