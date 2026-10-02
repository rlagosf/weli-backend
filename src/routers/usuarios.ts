// src/routers/usuarios.ts

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { z } from "zod";
import * as argon2 from "@node-rs/argon2";

import { db } from "../db";

import {
  blindIndex,
  decryptNullable,
  decryptRut,
  encryptNullable,
  encryptRut,
  rutBlindIndex,
  validateCryptoConfiguration,
} from "../services/crypto";

import { requireAuth, requireRoles, getEffectiveAcademiaId } from "../middlewares/authz";

/* =========================================================
   TIPOS DE AUTH
========================================================= */

type UserAuth = {
  type: "user";
  user_id?: number;
  rol_id?: number;
  academia_id?: number;
};

type ApoderadoAuth = {
  type: "apoderado";
  rut: string;
  apoderado_id?: number;
};

type AuthContext = UserAuth | ApoderadoAuth | undefined;

/* =========================================================
   AUTH HELPERS
========================================================= */

function getAuth(req: FastifyRequest): AuthContext {
  return (req as any).auth as AuthContext;
}

function getActorRol(req: FastifyRequest): number {
  const auth = getAuth(req);

  if (!auth || auth.type !== "user") {
    return 0;
  }

  return Number(auth.rol_id ?? 0);
}

function isSuper(req: FastifyRequest): boolean {
  return getActorRol(req) === 3;
}

function isAdmin(req: FastifyRequest): boolean {
  return getActorRol(req) === 1;
}

/* =========================================================
   RESPUESTAS
========================================================= */

function noStore(reply: FastifyReply) {
  reply.header("Cache-Control", "no-store");
}

function getErrorCode(err: any): number {
  if (err?.statusCode && Number.isFinite(Number(err.statusCode))) {
    return Number(err.statusCode);
  }

  return 500;
}

function duplicateFieldFromSqlMessage(message?: string): string | undefined {
  const text = String(message ?? "").toLowerCase();

  if (text.includes("rut_usuario_idx") || text.includes("rut_usuario")) {
    return "rut_usuario";
  }

  if (text.includes("email_idx") || text.includes("email")) {
    return "email";
  }

  if (text.includes("nombre_usuario_idx") || text.includes("nombre_usuario")) {
    return "nombre_usuario";
  }

  if (text.includes("academia")) {
    return "academia_id";
  }

  return undefined;
}

/* =========================================================
   NORMALIZACIONES
========================================================= */

function normalizeNombre(value: unknown): string {
  return String(value ?? "")
    .trim()
    .replace(/\s+/g, " ");
}

function normalizeNombreIndex(value: unknown): string {
  return normalizeNombre(value).toLocaleLowerCase("es-CL");
}

function normalizeEmail(value: unknown): string {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

function normalizeRutBody(value: unknown): string {
  const rut = String(value ?? "")
    .replace(/\D/g, "")
    .trim();

  if (!/^\d{7,8}$/.test(rut)) {
    throw Object.assign(new Error("rut_usuario inválido"), {
      statusCode: 400,
      field: "rut_usuario",
    });
  }

  return rut;
}

/* =========================================================
   CIFRADO
========================================================= */

function buildEncryptedIdentity(data: { nombre_usuario?: unknown; rut_usuario?: unknown; email?: unknown }) {
  const result: Record<string, any> = {};

  if (data.nombre_usuario !== undefined) {
    const nombre = normalizeNombre(data.nombre_usuario);

    if (!nombre) {
      throw Object.assign(new Error("nombre_usuario inválido"), {
        statusCode: 400,
        field: "nombre_usuario",
      });
    }

    result.nombre_usuario_enc = encryptNullable(nombre);

    result.nombre_usuario_idx = blindIndex(normalizeNombreIndex(nombre));
  }

  if (data.rut_usuario !== undefined) {
    const rut = normalizeRutBody(data.rut_usuario);

    result.rut_usuario_enc = encryptRut(rut);

    result.rut_usuario_idx = rutBlindIndex(rut);
  }

  if (data.email !== undefined) {
    const email = normalizeEmail(data.email);

    if (!email) {
      throw Object.assign(new Error("email inválido"), {
        statusCode: 400,
        field: "email",
      });
    }

    result.email_enc = encryptNullable(email);

    result.email_idx = blindIndex(email);
  }

  return result;
}

/* =========================================================
   DESCIFRADO
========================================================= */

function decryptText(encrypted: unknown): string | null {
  if (encrypted === null || encrypted === undefined || String(encrypted).trim() === "") {
    return null;
  }

  return decryptNullable(String(encrypted));
}

function decryptRutValue(encrypted: unknown): number | null {
  if (encrypted === null || encrypted === undefined || String(encrypted).trim() === "") {
    return null;
  }

  const value = decryptRut(String(encrypted));
  const numeric = Number(value);

  return Number.isFinite(numeric) ? numeric : null;
}

function normalizeUsuarioOut(row: any) {
  if (!row) {
    return null;
  }

  return {
    id: Number(row.id),

    academia_id: row.academia_id != null ? Number(row.academia_id) : null,

    nombre_usuario: decryptText(row.nombre_usuario_enc) ?? "",

    rut_usuario: decryptRutValue(row.rut_usuario_enc),

    email: decryptText(row.email_enc),

    rol_id: row.rol_id != null ? Number(row.rol_id) : null,

    estado_id: row.estado_id != null ? Number(row.estado_id) : null,
  };
}

/* =========================================================
   SCHEMAS
========================================================= */

const IdParam = z.object({
  id: z.coerce.number().int().positive(),
});

const RutParam = z.object({
  rut_usuario: z.string().regex(/^\d{7,8}$/, "El RUT debe contener 7 u 8 dígitos sin DV"),
});

const PageQuery = z.object({
  limit: z.coerce.number().int().positive().max(200).optional().default(50),

  offset: z.coerce.number().int().nonnegative().optional().default(0),

  q: z.string().trim().min(1).max(100).optional(),
});

const RutValueSchema = z.union([
  z.string().regex(/^\d{7,8}$/, "rut_usuario inválido"),

  z.number().int().min(1_000_000).max(99_999_999),
]);

const CreateSchema = z
  .object({
    /*
     * Se acepta por compatibilidad con el frontend,
     * pero el backend determinará finalmente
     * la academia efectiva mediante authz.
     */
    academia_id: z.coerce.number().int().positive().optional(),

    nombre_usuario: z
      .string()
      .trim()
      .min(1, "nombre_usuario es obligatorio")
      .max(150, "nombre_usuario demasiado largo"),

    rut_usuario: RutValueSchema,

    email: z.string().trim().email("email inválido").max(254),

    password: z.string().min(6, "password mínimo 6 caracteres").max(200, "password demasiado largo"),

    rol_id: z.coerce.number().int().positive(),

    estado_id: z.coerce.number().int().positive(),
  })
  .strict();

const UpdateSchema = z
  .object({
    academia_id: z.coerce.number().int().positive().optional(),

    nombre_usuario: z.string().trim().min(1).max(150).optional(),

    rut_usuario: RutValueSchema.optional(),

    email: z.string().trim().email().max(254).optional(),

    password: z.string().min(6).max(200).optional(),

    rol_id: z.coerce.number().int().positive().optional(),

    estado_id: z.coerce.number().int().positive().optional(),
  })
  .strict();

/* =========================================================
   REGLA PLATINO
========================================================= */

/**
 * Admin rol 1:
 *
 * - sólo puede asignar rol 1 o 2;
 * - nunca puede asignar rol 3.
 */
function assertAdminCanAssignRole(req: FastifyRequest, rolId: unknown) {
  if (!isAdmin(req)) {
    return;
  }

  const rid = Number(rolId);

  if (![1, 2].includes(rid)) {
    throw Object.assign(new Error("FORBIDDEN_ROLE_ASSIGNMENT"), {
      statusCode: 403,
      field: "rol_id",
    });
  }
}

/**
 * Admin rol 1 no puede modificar ni eliminar
 * una cuenta superadmin.
 */
async function assertTargetNotSuper(userId: number, req: FastifyRequest) {
  if (isSuper(req)) {
    return;
  }

  const [rows]: any = await db.query(
    `
      SELECT rol_id
      FROM usuarios
      WHERE id = ?
      LIMIT 1
    `,
    [userId]
  );

  const rolId = Number(rows?.[0]?.rol_id ?? 0);

  if (rolId === 3) {
    throw Object.assign(new Error("FORBIDDEN_TARGET_SUPERADMIN"), {
      statusCode: 403,
    });
  }
}

/* =========================================================
   TENANT
========================================================= */

function getAcademiaId(req: FastifyRequest): number {
  const academiaId = getEffectiveAcademiaId(req);

  const id = Number(academiaId);

  if (!Number.isInteger(id) || id <= 0) {
    throw Object.assign(new Error("ACADEMIA_REQUIRED"), {
      statusCode: 403,
    });
  }

  return id;
}

async function assertUserInAcademia(userId: number, academiaId: number) {
  const [rows]: any = await db.query(
    `
      SELECT id
      FROM usuarios
      WHERE id = ?
        AND academia_id = ?
      LIMIT 1
    `,
    [userId, academiaId]
  );

  if (!Array.isArray(rows) || rows.length === 0) {
    throw Object.assign(new Error("No encontrado"), {
      statusCode: 404,
    });
  }
}

/* =========================================================
   DUPLICADOS
========================================================= */

async function assertRutDisponible(rut: unknown, excludeUserId?: number) {
  const rutNormalizado = normalizeRutBody(rut);

  const rutIdx = rutBlindIndex(rutNormalizado);

  let sql = `
    SELECT id
    FROM usuarios
    WHERE rut_usuario_idx = ?
  `;

  const args: any[] = [rutIdx];

  if (excludeUserId !== undefined && excludeUserId !== null) {
    sql += " AND id <> ?";
    args.push(excludeUserId);
  }

  sql += " LIMIT 1";

  const [rows]: any = await db.query(sql, args);

  if (rows?.length) {
    throw Object.assign(new Error("Duplicado: el RUT ya existe"), {
      statusCode: 409,
      field: "rut_usuario",
    });
  }
}

async function assertEmailDisponible(email: unknown, excludeUserId?: number) {
  const normalizado = normalizeEmail(email);

  const emailIdx = blindIndex(normalizado);

  let sql = `
    SELECT id
    FROM usuarios
    WHERE email_idx = ?
  `;

  const args: any[] = [emailIdx];

  if (excludeUserId !== undefined && excludeUserId !== null) {
    sql += " AND id <> ?";
    args.push(excludeUserId);
  }

  sql += " LIMIT 1";

  const [rows]: any = await db.query(sql, args);

  if (rows?.length) {
    throw Object.assign(new Error("Duplicado: el email ya existe"), {
      statusCode: 409,
      field: "email",
    });
  }
}

/* =========================================================
   ROUTER
========================================================= */

export default async function usuarios(app: FastifyInstance) {
  /*
   * El router no queda operativo
   * si crypto no está correctamente configurado.
   */
  validateCryptoConfiguration();

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
    async (_req, reply) => {
      noStore(reply);

      return reply.send({
        module: "usuarios",
        status: "ready",
        timestamp: new Date().toISOString(),
      });
    }
  );

  /* =======================================================
     LIST
  ======================================================= */

  app.get(
    "/",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      noStore(reply);

      const parsed = PageQuery.safeParse((req as any).query);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "Query inválida",
          detail: parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; "),
        });
      }

      try {
        const { limit, offset, q } = parsed.data;

        const academiaId = getAcademiaId(req);

        const args: any[] = [academiaId];

        let sql = `
          SELECT
            id,
            academia_id,

            nombre_usuario_enc,

            rut_usuario_enc,
            rut_usuario_idx,

            email_enc,

            rol_id,
            estado_id

          FROM usuarios

          WHERE academia_id = ?
        `;

        /*
         * RUT completo:
         * utilizamos blind index y evitamos
         * descifrar registros innecesarios.
         */
        const exactRut = Boolean(q && /^\d{7,8}$/.test(q));

        if (exactRut && q) {
          sql += " AND rut_usuario_idx = ?";

          args.push(rutBlindIndex(q));
        }

        sql += " ORDER BY id ASC";

        const [rows]: any = await db.query(sql, args);

        let items = (Array.isArray(rows) ? rows : []).map(normalizeUsuarioOut).filter(Boolean);

        /*
         * Nombre y email están cifrados con
         * AES-GCM y por tanto no admiten LIKE.
         *
         * Para búsqueda parcial:
         * 1. restringimos primero por tenant;
         * 2. desciframos;
         * 3. filtramos en memoria.
         */
        if (q && !exactRut) {
          const needle = String(q).trim().toLocaleLowerCase("es-CL");

          items = items.filter((item: any) => {
            const nombre = String(item?.nombre_usuario ?? "").toLocaleLowerCase("es-CL");

            const email = String(item?.email ?? "").toLowerCase();

            const rut = String(item?.rut_usuario ?? "");

            return nombre.includes(needle) || email.includes(needle) || rut.includes(needle);
          });
        }

        items.sort((a: any, b: any) =>
          String(a?.nombre_usuario ?? "").localeCompare(String(b?.nombre_usuario ?? ""), "es", {
            sensitivity: "base",
          })
        );

        const total = items.length;

        const paginated = items.slice(offset, offset + limit);

        return reply.send({
          ok: true,

          items: paginated,

          limit,
          offset,

          count: paginated.length,

          total,

          filters: {
            q: q ?? null,
          },
        });
      } catch (err: any) {
        const code = getErrorCode(err);

        return reply.code(code).send({
          ok: false,

          message: code === 403 ? "Acceso denegado" : "Error al listar usuarios",

          detail: err?.sqlMessage ?? err?.message,
        });
      }
    }
  );

  /* =======================================================
     GET BY RUT

     IMPORTANTE:
     debe ir antes de /:id
  ======================================================= */

  app.get(
    "/rut/:rut_usuario",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      noStore(reply);

      const parsed = RutParam.safeParse((req as any).params);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "RUT inválido",
        });
      }

      try {
        const academiaId = getAcademiaId(req);

        const rutIdx = rutBlindIndex(parsed.data.rut_usuario);

        const [rows]: any = await db.query(
          `
              SELECT
                id,
                academia_id,

                nombre_usuario_enc,

                rut_usuario_enc,
                rut_usuario_idx,

                email_enc,

                rol_id,
                estado_id

              FROM usuarios

              WHERE academia_id = ?
                AND rut_usuario_idx = ?

              ORDER BY id DESC
            `,
          [academiaId, rutIdx]
        );

        return reply.send({
          ok: true,

          items: (rows ?? []).map(normalizeUsuarioOut),
        });
      } catch (err: any) {
        const code = getErrorCode(err);

        return reply.code(code).send({
          ok: false,

          message: code === 403 ? "Acceso denegado" : "Error al buscar por RUT",

          detail: err?.sqlMessage ?? err?.message,
        });
      }
    }
  );

  /* =======================================================
     GET BY ID
  ======================================================= */

  app.get(
    "/:id",
    {
      preHandler: canRead,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      noStore(reply);

      const parsed = IdParam.safeParse((req as any).params);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      try {
        const academiaId = getAcademiaId(req);

        const [rows]: any = await db.query(
          `
              SELECT
                id,
                academia_id,

                nombre_usuario_enc,

                rut_usuario_enc,
                rut_usuario_idx,

                email_enc,

                rol_id,
                estado_id

              FROM usuarios

              WHERE id = ?
                AND academia_id = ?

              LIMIT 1
            `,
          [parsed.data.id, academiaId]
        );

        if (!rows?.length) {
          return reply.code(404).send({
            ok: false,
            message: "No encontrado",
          });
        }

        return reply.send({
          ok: true,

          item: normalizeUsuarioOut(rows[0]),
        });
      } catch (err: any) {
        const code = getErrorCode(err);

        return reply.code(code).send({
          ok: false,

          message: code === 403 ? "Acceso denegado" : "Error al obtener usuario",

          detail: err?.sqlMessage ?? err?.message,
        });
      }
    }
  );

  /* =======================================================
     CREATE
  ======================================================= */

  app.post(
    "/",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      noStore(reply);

      const parsed = CreateSchema.safeParse((req as any).body);

      if (!parsed.success) {
        const detail = parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");

        return reply.code(400).send({
          ok: false,
          message: "Payload inválido",
          detail,
        });
      }

      try {
        /*
         * Tenant efectivo:
         *
         * - rol 1: academia JWT
         * - rol 3: academia seleccionada
         */
        const academiaId = getAcademiaId(req);

        const body = parsed.data;

        assertAdminCanAssignRole(req, body.rol_id);

        const nombre = normalizeNombre(body.nombre_usuario);

        const rut = normalizeRutBody(body.rut_usuario);

        const email = normalizeEmail(body.email);

        /*
         * Comprobaciones anticipadas para
         * devolver errores más claros.
         */
        await assertRutDisponible(rut);

        await assertEmailDisponible(email);

        const crypto = buildEncryptedIdentity({
          nombre_usuario: nombre,

          rut_usuario: rut,

          email,
        });

        /*
         * Password exclusivamente Argon2.
         */
        const passwordHash = await argon2.hash(String(body.password));

        const [result]: any = await db.query(
          `
              INSERT INTO usuarios
              (
                academia_id,

                nombre_usuario_enc,
                nombre_usuario_idx,

                rut_usuario_enc,
                rut_usuario_idx,

                email_enc,
                email_idx,

                password,

                rol_id,
                estado_id
              )
              VALUES
              (
                ?,

                ?,
                ?,

                ?,
                ?,

                ?,
                ?,

                ?,

                ?,
                ?
              )
            `,
          [
            academiaId,

            crypto.nombre_usuario_enc,

            crypto.nombre_usuario_idx,

            crypto.rut_usuario_enc,

            crypto.rut_usuario_idx,

            crypto.email_enc,
            crypto.email_idx,

            passwordHash,

            Number(body.rol_id),

            Number(body.estado_id),
          ]
        );

        const userId = Number(result?.insertId ?? 0);

        if (!Number.isInteger(userId) || userId <= 0) {
          throw new Error("No fue posible obtener el ID del usuario creado");
        }

        return reply.code(201).send({
          ok: true,

          id: userId,

          item: {
            id: userId,

            academia_id: academiaId,

            nombre_usuario: nombre,

            rut_usuario: Number(rut),

            email,

            rol_id: Number(body.rol_id),

            estado_id: Number(body.estado_id),
          },
        });
      } catch (err: any) {
        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "Usuario duplicado (email o RUT ya existe)",

            field: duplicateFieldFromSqlMessage(err?.sqlMessage),

            detail: err?.sqlMessage ?? err?.message,
          });
        }

        if (err?.errno === 1452 || err?.code === "ER_NO_REFERENCED_ROW_2") {
          return reply.code(409).send({
            ok: false,

            message: "Violación de clave foránea (academia_id, rol_id o estado_id inválido)",

            detail: err?.sqlMessage ?? err?.message,
          });
        }

        if (err?.errno === 1054 || err?.code === "ER_BAD_FIELD_ERROR") {
          return reply.code(500).send({
            ok: false,

            message: "Columna desconocida: revisa el esquema de usuarios",

            detail: err?.sqlMessage ?? err?.message,
          });
        }

        const code = getErrorCode(err);

        return reply.code(code).send({
          ok: false,

          field: err?.field,

          message:
            code === 403 ? (err?.message ?? "Acceso denegado") : code === 409 ? err?.message : "Error al crear usuario",

          detail: err?.sqlMessage ?? err?.message,
        });
      }
    }
  );

  /* =======================================================
     UPDATE
  ======================================================= */

  app.put(
    "/:id",
    {
      preHandler: canWrite,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      noStore(reply);

      const pid = IdParam.safeParse((req as any).params);

      if (!pid.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      const parsed = UpdateSchema.safeParse((req as any).body);

      if (!parsed.success) {
        const detail = parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");

        return reply.code(400).send({
          ok: false,
          message: "Payload inválido",
          detail,
        });
      }

      try {
        const id = pid.data.id;

        const academiaId = getAcademiaId(req);

        /*
         * El usuario objetivo debe pertenecer
         * a la academia efectiva.
         */
        await assertUserInAcademia(id, academiaId);

        await assertTargetNotSuper(id, req);

        const body = {
          ...parsed.data,
        };

        /*
         * Admin nunca puede cambiar academia.
         *
         * Superadmin puede mover usuario sólo
         * si academia_id fue explícitamente enviada.
         */
        if (isAdmin(req)) {
          delete body.academia_id;
        }

        if (body.rol_id !== undefined) {
          assertAdminCanAssignRole(req, body.rol_id);
        }

        if (body.rut_usuario !== undefined) {
          await assertRutDisponible(body.rut_usuario, id);
        }

        if (body.email !== undefined) {
          await assertEmailDisponible(body.email, id);
        }

        const setClauses: string[] = [];

        const values: any[] = [];

        const publicChanges: Record<string, any> = {};

        /* -----------------------------------------
           ACADEMIA
        ----------------------------------------- */

        if (body.academia_id !== undefined) {
          const nuevaAcademia = Number(body.academia_id);

          if (!Number.isInteger(nuevaAcademia) || nuevaAcademia <= 0) {
            throw Object.assign(new Error("academia_id inválido"), {
              statusCode: 400,
              field: "academia_id",
            });
          }

          setClauses.push("academia_id = ?");

          values.push(nuevaAcademia);

          publicChanges.academia_id = nuevaAcademia;
        }

        /* -----------------------------------------
           NOMBRE
        ----------------------------------------- */

        if (body.nombre_usuario !== undefined) {
          const nombre = normalizeNombre(body.nombre_usuario);

          const crypto = buildEncryptedIdentity({
            nombre_usuario: nombre,
          });

          setClauses.push("nombre_usuario_enc = ?", "nombre_usuario_idx = ?");

          values.push(
            crypto.nombre_usuario_enc,

            crypto.nombre_usuario_idx
          );

          publicChanges.nombre_usuario = nombre;
        }

        /* -----------------------------------------
           RUT
        ----------------------------------------- */

        if (body.rut_usuario !== undefined) {
          const rut = normalizeRutBody(body.rut_usuario);

          const crypto = buildEncryptedIdentity({
            rut_usuario: rut,
          });

          setClauses.push("rut_usuario_enc = ?", "rut_usuario_idx = ?");

          values.push(
            crypto.rut_usuario_enc,

            crypto.rut_usuario_idx
          );

          publicChanges.rut_usuario = Number(rut);
        }

        /* -----------------------------------------
           EMAIL
        ----------------------------------------- */

        if (body.email !== undefined) {
          const email = normalizeEmail(body.email);

          const crypto = buildEncryptedIdentity({
            email,
          });

          setClauses.push("email_enc = ?", "email_idx = ?");

          values.push(crypto.email_enc, crypto.email_idx);

          publicChanges.email = email;
        }

        /* -----------------------------------------
           PASSWORD
        ----------------------------------------- */

        if (body.password !== undefined) {
          const passwordHash = await argon2.hash(String(body.password));

          setClauses.push("password = ?");

          values.push(passwordHash);
        }

        /* -----------------------------------------
           ROL
        ----------------------------------------- */

        if (body.rol_id !== undefined) {
          setClauses.push("rol_id = ?");

          values.push(Number(body.rol_id));

          publicChanges.rol_id = Number(body.rol_id);
        }

        /* -----------------------------------------
           ESTADO
        ----------------------------------------- */

        if (body.estado_id !== undefined) {
          setClauses.push("estado_id = ?");

          values.push(Number(body.estado_id));

          publicChanges.estado_id = Number(body.estado_id);
        }

        if (setClauses.length === 0) {
          return reply.code(400).send({
            ok: false,
            message: "No hay campos para actualizar",
          });
        }

        values.push(id, academiaId);

        const [result]: any = await db.query(
          `
              UPDATE usuarios

              SET
                ${setClauses.join(", ")}

              WHERE id = ?
                AND academia_id = ?
            `,
          values
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
            ...publicChanges,
          },
        });
      } catch (err: any) {
        if (err?.errno === 1062 || err?.code === "ER_DUP_ENTRY") {
          return reply.code(409).send({
            ok: false,

            message: "Usuario duplicado (email o RUT ya existe)",

            field: duplicateFieldFromSqlMessage(err?.sqlMessage),

            detail: err?.sqlMessage ?? err?.message,
          });
        }

        if (err?.errno === 1452) {
          return reply.code(409).send({
            ok: false,

            message: "Violación de clave foránea (academia_id, rol_id o estado_id inválido)",

            detail: err?.sqlMessage ?? err?.message,
          });
        }

        const code = getErrorCode(err);

        return reply.code(code).send({
          ok: false,

          field: err?.field,

          message:
            code === 404
              ? "No encontrado"
              : code === 403
                ? (err?.message ?? "Acceso denegado")
                : code === 409
                  ? err?.message
                  : "Error al actualizar usuario",

          detail: err?.sqlMessage ?? err?.message,
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
      noStore(reply);

      const parsed = IdParam.safeParse((req as any).params);

      if (!parsed.success) {
        return reply.code(400).send({
          ok: false,
          message: "ID inválido",
        });
      }

      try {
        const id = parsed.data.id;

        const academiaId = getAcademiaId(req);

        await assertUserInAcademia(id, academiaId);

        await assertTargetNotSuper(id, req);

        const [result]: any = await db.query(
          `
              DELETE FROM usuarios

              WHERE id = ?
                AND academia_id = ?
            `,
          [id, academiaId]
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
        });
      } catch (err: any) {
        if (err?.errno === 1451 || err?.code === "ER_ROW_IS_REFERENCED_2") {
          return reply.code(409).send({
            ok: false,

            message: "No se puede eliminar: hay registros vinculados a este usuario.",

            detail: err?.sqlMessage ?? err?.message,
          });
        }

        const code = getErrorCode(err);

        return reply.code(code).send({
          ok: false,

          message:
            code === 404
              ? "No encontrado"
              : code === 403
                ? (err?.message ?? "Acceso denegado")
                : "Error al eliminar usuario",

          detail: err?.sqlMessage ?? err?.message,
        });
      }
    }
  );
}
