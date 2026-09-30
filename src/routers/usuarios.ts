// src/routers/usuarios.ts

import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
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

import { requireAuth, requireRoles } from "../middlewares/authz";

/**
 * Tabla: usuarios
 *
 * Columnas funcionales:
 *  id,
 *  academia_id,
 *  nombre_usuario,
 *  rut_usuario,
 *  email,
 *  password,
 *  rol_id,
 *  estado_id
 *
 * Columnas criptográficas:
 *  nombre_usuario_enc
 *  nombre_usuario_idx
 *  rut_usuario_enc
 *  rut_usuario_idx
 *  email_enc
 *  email_idx
 *
 * Reglas WELI:
 *
 * - READ: roles 1 y 3
 * - WRITE: roles 1 y 3
 *
 * Scope academia:
 *
 * - rol 1:
 *     solo su academia_id;
 *     al crear SIEMPRE se fuerza a su academia.
 *
 * - rol 3:
 *     bypass multiacademia.
 *
 * Regla Platino:
 *
 * - Actor rol 1 NO puede crear/editar usuarios rol 3.
 * - Actor rol 1 solo puede asignar rol_id ∈ {1,2}.
 * - Actor rol 1 NO puede editar/borrar una cuenta cuyo rol actual sea 3.
 *
 * Seguridad criptográfica:
 *
 * - nombre_usuario, rut_usuario y email se mantienen temporalmente
 *   en dual-write durante la fase de transición.
 *
 * - las lecturas priorizan *_enc.
 *
 * - las búsquedas exactas por RUT utilizan rut_usuario_idx.
 *
 * - password continúa siendo hash Argon2 irreversible.
 *
 * - *_enc y *_idx jamás provienen desde el frontend.
 */

/* =========================================================
   AUTH HELPERS
========================================================= */

function getAuth(req: any) {
  return (req as any).auth as
    | {
        type: "user";
        user_id?: number;
        rol_id?: number;
        academia_id?: number;
      }
    | {
        type: "apoderado";
        rut: string;
        apoderado_id?: number;
      }
    | undefined;
}

function getActorRol(req: any): number {
  const auth = getAuth(req);

  return auth?.type === "user" ? Number(auth.rol_id ?? 0) : 0;
}

function isSuper(req: any) {
  return getActorRol(req) === 3;
}

function isAdmin(req: any) {
  return getActorRol(req) === 1;
}

/**
 * Devuelve:
 *
 * - null para superadmin;
 * - academia_id para admin;
 * - responde 403 si el contexto no es válido.
 */
function getAcademiaIdOr403(req: any, reply: FastifyReply): number | null {
  const auth = getAuth(req);

  if (!auth || auth.type !== "user") {
    reply.code(403).send({
      ok: false,
      message: "FORBIDDEN",
    });

    return 0 as any;
  }

  if (Number(auth.rol_id) === 3) {
    return null;
  }

  const academiaId = Number(auth.academia_id ?? 0);

  if (!Number.isFinite(academiaId) || academiaId <= 0) {
    reply.code(403).send({
      ok: false,
      message: "ACADEMIA_REQUIRED",
    });

    return 0 as any;
  }

  return academiaId;
}

async function assertUserInAcademiaOr404(id: number, academiaId: number | null, reply: FastifyReply) {
  if (!academiaId) {
    return true;
  }

  const [rows]: any = await db.query(
    `
      SELECT id
      FROM usuarios
      WHERE id = ?
        AND academia_id = ?
      LIMIT 1
    `,
    [id, academiaId]
  );

  if (!rows?.length) {
    /*
     * 404 deliberado para no filtrar
     * información entre tenants.
     */
    reply.code(404).send({
      ok: false,
      message: "No encontrado",
    });

    return false;
  }

  return true;
}

/**
 * Regla Platino:
 *
 * Admin rol 1:
 *
 * - no puede asignar rol 3;
 * - sólo puede asignar roles 1 y 2.
 */
function assertAdminCannotAssignSuperOr403(req: any, rolId: any, reply: FastifyReply) {
  if (!isAdmin(req) || isSuper(req)) {
    return;
  }

  const rid = Number(rolId);

  if (rid === 3 || ![1, 2].includes(rid)) {
    reply.code(403).send({
      ok: false,
      message: "FORBIDDEN_ROLE_ASSIGNMENT",
    });

    throw new Error("FORBIDDEN_ROLE_ASSIGNMENT");
  }
}

/**
 * Regla Platino:
 *
 * Admin rol 1 no puede modificar ni borrar
 * una cuenta cuyo rol actual sea superadmin.
 */
async function assertTargetNotSuperOr403(targetUserId: number, req: any, reply: FastifyReply) {
  if (isSuper(req)) {
    return true;
  }

  const [rows]: any = await db.query(
    `
        SELECT rol_id
        FROM usuarios
        WHERE id = ?
        LIMIT 1
      `,
    [targetUserId]
  );

  const rid = Number(rows?.[0]?.rol_id ?? 0);

  if (rid === 3) {
    reply.code(403).send({
      ok: false,
      message: "FORBIDDEN_TARGET_SUPERADMIN",
    });

    return false;
  }

  return true;
}

/* =========================================================
   RESPONSE / ERROR HELPERS
========================================================= */

function noStore(reply: FastifyReply) {
  reply.header("Cache-Control", "no-store");
}

function duplicateFieldFromSqlMessage(msg?: string) {
  const text = String(msg || "").toLowerCase();

  if (text.includes("email")) {
    return "email";
  }

  if (text.includes("rut")) {
    return "rut_usuario";
  }

  if (text.includes("nombre_usuario")) {
    return "nombre_usuario";
  }

  if (text.includes("academia")) {
    return "academia_id";
  }

  return undefined;
}

/**
 * Escape mínimo para LIKE.
 *
 * Durante la fase dual se mantiene la búsqueda
 * parcial sobre columnas legacy para no romper
 * la funcionalidad existente.
 */
function escapeLike(value: string) {
  return value.replace(/[\\%_]/g, (match) => `\\${match}`);
}

/* =========================================================
   NORMALIZACIONES CRIPTOGRÁFICAS
========================================================= */

function normalizeUsernameIndex(value: unknown): string {
  const normalized = String(value ?? "")
    .trim()
    .toLowerCase();

  if (!normalized) {
    throw new Error("nombre_usuario inválido");
  }

  return normalized;
}

function normalizeEmailIndex(value: unknown): string {
  const normalized = String(value ?? "")
    .trim()
    .toLowerCase();

  if (!normalized) {
    throw new Error("email inválido");
  }

  return normalized;
}

/**
 * Añade los mirrors criptográficos.
 *
 * Nunca recibe *_enc o *_idx desde el cliente:
 * allowedKeys los excluye.
 */
function applyEncryptedMirrors(target: Record<string, any>) {
  if ("nombre_usuario" in target) {
    if (
      target.nombre_usuario === null ||
      target.nombre_usuario === undefined ||
      String(target.nombre_usuario).trim() === ""
    ) {
      target.nombre_usuario_enc = null;

      target.nombre_usuario_idx = null;
    } else {
      const nombre = String(target.nombre_usuario).trim();

      target.nombre_usuario_enc = encryptNullable(nombre);

      target.nombre_usuario_idx = blindIndex(normalizeUsernameIndex(nombre));
    }
  }

  if ("rut_usuario" in target) {
    if (target.rut_usuario === null || target.rut_usuario === undefined || target.rut_usuario === "") {
      target.rut_usuario_enc = null;

      target.rut_usuario_idx = null;
    } else {
      target.rut_usuario_enc = encryptRut(target.rut_usuario);

      target.rut_usuario_idx = rutBlindIndex(target.rut_usuario);
    }
  }

  if ("email" in target) {
    if (target.email === null || target.email === undefined || String(target.email).trim() === "") {
      target.email_enc = null;
      target.email_idx = null;
    } else {
      const email = normalizeEmailIndex(target.email);

      target.email_enc = encryptNullable(email);

      target.email_idx = blindIndex(email);
    }
  }
}

/* =========================================================
   DESCIFRADO DE RESPUESTAS
========================================================= */

function decryptTextOrLegacy(encrypted: unknown, legacy: unknown): string | null {
  if (encrypted !== null && encrypted !== undefined && String(encrypted).trim() !== "") {
    return decryptNullable(String(encrypted));
  }

  if (legacy === null || legacy === undefined) {
    return null;
  }

  return String(legacy);
}

function decryptRutOrLegacy(encrypted: unknown, legacy: unknown): number | null {
  if (encrypted !== null && encrypted !== undefined && String(encrypted).trim() !== "") {
    const decrypted = decryptRut(String(encrypted));

    const numeric = Number(decrypted);

    return Number.isFinite(numeric) ? numeric : null;
  }

  if (legacy === null || legacy === undefined || legacy === "") {
    return null;
  }

  const numeric = Number(legacy);

  return Number.isFinite(numeric) ? numeric : null;
}

function normalizeUsuarioOut(row: any) {
  if (!row) {
    return null;
  }

  return {
    id: Number(row.id),

    academia_id: row.academia_id != null ? Number(row.academia_id) : null,

    nombre_usuario: decryptTextOrLegacy(row.nombre_usuario_enc, row.nombre_usuario) ?? "",

    rut_usuario: decryptRutOrLegacy(row.rut_usuario_enc, row.rut_usuario),

    email: decryptTextOrLegacy(row.email_enc, row.email),

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

/**
 * WELI:
 *
 * RUT interno = cuerpo numérico,
 * sin puntos,
 * sin guion,
 * sin DV,
 * 7 u 8 dígitos.
 */
const RutParam = z.object({
  rut_usuario: z.string().regex(/^\d{7,8}$/, "RUT inválido"),
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
     * Requerido sólo si crea un superadmin.
     *
     * Para rol 1 el valor recibido se ignora
     * y se fuerza el tenant del JWT.
     */
    academia_id: z.coerce.number().int().positive().optional(),

    nombre_usuario: z.string().trim().min(1, "nombre_usuario es obligatorio"),

    rut_usuario: RutValueSchema,

    email: z.string().trim().email("email inválido"),

    password: z.string().min(6, "password mínimo 6 caracteres"),

    rol_id: z.coerce.number().int().positive(),

    estado_id: z.coerce.number().int().positive(),
  })
  .strict();

const UpdateSchema = z
  .object({
    /*
     * Sólo rol 3 puede mover academia_id.
     */
    academia_id: z.coerce.number().int().positive().optional(),

    nombre_usuario: z.string().trim().min(1).optional(),

    rut_usuario: RutValueSchema.optional(),

    email: z.string().trim().email().optional(),

    password: z.string().min(6).optional(),

    rol_id: z.coerce.number().int().positive().optional(),

    estado_id: z.coerce.number().int().positive().optional(),
  })
  .strict();

/**
 * Whitelist pública.
 *
 * Deliberadamente NO contiene:
 *
 * nombre_usuario_enc
 * nombre_usuario_idx
 * rut_usuario_enc
 * rut_usuario_idx
 * email_enc
 * email_idx
 */
const allowedKeys = new Set([
  "academia_id",
  "nombre_usuario",
  "rut_usuario",
  "email",
  "password",
  "rol_id",
  "estado_id",
]);

function pickAllowed(body: Record<string, unknown>) {
  const out: Record<string, unknown> = {};

  for (const key in body) {
    if (allowedKeys.has(key)) {
      out[key] = (body as any)[key];
    }
  }

  return out;
}

function normalizeForDB(input: Record<string, unknown>) {
  const out: Record<string, any> = {
    ...input,
  };

  if (out.academia_id != null) {
    out.academia_id = Number(out.academia_id);
  }

  if (typeof out.nombre_usuario === "string") {
    out.nombre_usuario = out.nombre_usuario.trim();
  }

  if (typeof out.email === "string") {
    out.email = out.email.trim().toLowerCase();
  }

  if (out.rut_usuario != null && out.rut_usuario !== "") {
    const rutN = Number(out.rut_usuario);

    out.rut_usuario = Number.isNaN(rutN) ? null : rutN;
  }

  if (out.rol_id != null) {
    out.rol_id = Number(out.rol_id);
  }

  if (out.estado_id != null) {
    out.estado_id = Number(out.estado_id);
  }

  for (const key of Object.keys(out)) {
    if (out[key] === "") {
      out[key] = null;
    }
  }

  return out;
}

/* =========================================================
   ROUTER
========================================================= */

export default async function usuarios(app: FastifyInstance) {
  /*
   * Fail-fast.
   *
   * Este router no debe quedar operativo
   * sin las claves criptográficas.
   */
  validateCryptoConfiguration();

  /*
   * READ / WRITE:
   * roles 1 y 3.
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
    async (_req, reply) => {
      noStore(reply);

      return {
        module: "usuarios",
        status: "ready",
        timestamp: new Date().toISOString(),
      };
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

      const { limit, offset, q } = parsed.success
        ? parsed.data
        : {
            limit: 50,
            offset: 0,
            q: undefined,
          };

      const academiaId = getAcademiaIdOr403(req, reply);

      if ((reply as any).sent) {
        return;
      }

      try {
        let sql = `
          SELECT
            id,
            academia_id,

            nombre_usuario,
            nombre_usuario_enc,

            rut_usuario,
            rut_usuario_enc,

            email,
            email_enc,

            rol_id,
            estado_id

          FROM usuarios

          WHERE 1 = 1
        `;

        const args: any[] = [];

        if (academiaId) {
          sql += " AND academia_id = ?";

          args.push(academiaId);
        }

        /*
         * IMPORTANTE:
         *
         * AES-GCM no admite LIKE.
         *
         * Durante la fase dual mantenemos
         * nombre_usuario/email/rut legacy
         * exclusivamente para búsqueda parcial
         * y ordenamiento.
         *
         * Para RUT completo de 7 u 8 dígitos
         * utilizamos además el blind index.
         */
        if (q) {
          const like = `%${escapeLike(q)}%`;

          if (/^\d{7,8}$/.test(q)) {
            sql += `
              AND (
                rut_usuario_idx = ?
                OR nombre_usuario LIKE ? ESCAPE '\\\\'
                OR email LIKE ? ESCAPE '\\\\'
                OR CAST(rut_usuario AS CHAR) LIKE ? ESCAPE '\\\\'
              )
            `;

            args.push(rutBlindIndex(q), like, like, like);
          } else {
            sql += `
              AND (
                nombre_usuario LIKE ? ESCAPE '\\\\'
                OR email LIKE ? ESCAPE '\\\\'
                OR CAST(rut_usuario AS CHAR) LIKE ? ESCAPE '\\\\'
              )
            `;

            args.push(like, like, like);
          }
        }

        /*
         * Orden temporal legacy.
         *
         * Con AES-GCM aleatorio no podemos
         * ORDER BY nombre_usuario_enc.
         */
        sql += `
          ORDER BY
            nombre_usuario ASC,
            id ASC

          LIMIT ?
          OFFSET ?
        `;

        args.push(limit, offset);

        const [rows]: any = await db.query(sql, args);

        return reply.send({
          ok: true,

          items: (rows ?? []).map(normalizeUsuarioOut),

          limit,
          offset,

          count: rows?.length ?? 0,

          filters: {
            q: q ?? null,
          },
        });
      } catch (err: any) {
        return reply.code(500).send({
          ok: false,

          message: "Error al listar usuarios",

          detail: err?.message,
        });
      }
    }
  );

  /*
   * IMPORTANTE:
   *
   * /rut/:rut_usuario debe declararse
   * ANTES de /:id.
   */

  /* =======================================================
     GET BY RUT
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

      const academiaId = getAcademiaIdOr403(req, reply);

      if ((reply as any).sent) {
        return;
      }

      try {
        const rutIdx = rutBlindIndex(parsed.data.rut_usuario);

        let sql = `
          SELECT
            id,
            academia_id,

            nombre_usuario,
            nombre_usuario_enc,

            rut_usuario,
            rut_usuario_enc,

            email,
            email_enc,

            rol_id,
            estado_id

          FROM usuarios

          WHERE rut_usuario_idx = ?
        `;

        const args: any[] = [rutIdx];

        if (academiaId) {
          sql += " AND academia_id = ?";

          args.push(academiaId);
        }

        sql += " ORDER BY id DESC";

        const [rows]: any = await db.query(sql, args);

        return reply.send({
          ok: true,

          items: (rows ?? []).map(normalizeUsuarioOut),
        });
      } catch (err: any) {
        return reply.code(500).send({
          ok: false,

          message: "Error al buscar por RUT",

          detail: err?.message,
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

      const academiaId = getAcademiaIdOr403(req, reply);

      if ((reply as any).sent) {
        return;
      }

      try {
        let sql = `
          SELECT
            id,
            academia_id,

            nombre_usuario,
            nombre_usuario_enc,

            rut_usuario,
            rut_usuario_enc,

            email,
            email_enc,

            rol_id,
            estado_id

          FROM usuarios

          WHERE id = ?
        `;

        const args: any[] = [parsed.data.id];

        if (academiaId) {
          sql += " AND academia_id = ?";

          args.push(academiaId);
        }

        sql += " LIMIT 1";

        const [rows]: any = await db.query(sql, args);

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
        return reply.code(500).send({
          ok: false,

          message: "Error al obtener usuario",

          detail: err?.message,
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

      const academiaId = getAcademiaIdOr403(req, reply);

      if ((reply as any).sent) {
        return;
      }

      const data: any = normalizeForDB(pickAllowed(parsed.data));

      /*
       * rol 1:
       * SIEMPRE fuerza academia del JWT.
       *
       * rol 3:
       * debe indicar academia_id.
       */
      if (academiaId) {
        data.academia_id = academiaId;
      } else {
        if (!data.academia_id || !Number.isFinite(Number(data.academia_id)) || Number(data.academia_id) <= 0) {
          return reply.code(400).send({
            ok: false,

            message: "academia_id es obligatorio para superadmin",
          });
        }
      }

      if (
        !data.nombre_usuario ||
        !data.email ||
        !data.password ||
        !data.rut_usuario ||
        !data.rol_id ||
        !data.estado_id
      ) {
        return reply.code(400).send({
          ok: false,

          message: "Payload inválido (campos requeridos faltantes)",
        });
      }

      /*
       * Regla Platino.
       */
      try {
        assertAdminCannotAssignSuperOr403(req, data.rol_id, reply);
      } catch {
        return;
      }

      if ((reply as any).sent) {
        return;
      }

      try {
        /*
         * Generamos cifrado e índices ANTES
         * de reemplazar password por su hash.
         */
        applyEncryptedMirrors(data);

        /*
         * password:
         *
         * siempre hash Argon2.
         *
         * Nunca AES.
         */
        data.password = await argon2.hash(String(data.password));

        const [result]: any = await db.query(
          `
              INSERT INTO usuarios
              (
                academia_id,

                nombre_usuario,
                nombre_usuario_enc,
                nombre_usuario_idx,

                rut_usuario,
                rut_usuario_enc,
                rut_usuario_idx,

                email,
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
                ?,

                ?,

                ?,
                ?
              )
            `,
          [
            data.academia_id,

            data.nombre_usuario,
            data.nombre_usuario_enc,
            data.nombre_usuario_idx,

            data.rut_usuario,
            data.rut_usuario_enc,
            data.rut_usuario_idx,

            data.email,
            data.email_enc,
            data.email_idx,

            data.password,

            data.rol_id,
            data.estado_id,
          ]
        );

        return reply.code(201).send({
          ok: true,

          id: result.insertId,

          academia_id: data.academia_id,

          /*
           * Se devuelve el contrato funcional,
           * nunca ciphertext ni índices.
           */
          nombre_usuario: data.nombre_usuario,

          rut_usuario: data.rut_usuario,

          email: data.email,

          rol_id: data.rol_id,

          estado_id: data.estado_id,
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

        return reply.code(500).send({
          ok: false,

          message: "Error al crear usuario",

          detail: err?.message,
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

      const id = pid.data.id;

      const parsed = UpdateSchema.safeParse((req as any).body);

      if (!parsed.success) {
        const detail = parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");

        return reply.code(400).send({
          ok: false,
          message: "Payload inválido",
          detail,
        });
      }

      const academiaId = getAcademiaIdOr403(req, reply);

      if ((reply as any).sent) {
        return;
      }

      /*
       * Admin:
       * no puede editar fuera de su academia.
       */
      const okRow = await assertUserInAcademiaOr404(id, academiaId, reply);

      if (!okRow) {
        return;
      }

      /*
       * Regla Platino:
       *
       * admin no puede modificar superadmin.
       */
      const okTarget = await assertTargetNotSuperOr403(id, req, reply);

      if (!okTarget) {
        return;
      }

      const changes: any = normalizeForDB(pickAllowed(parsed.data));

      if (Object.keys(changes).length === 0) {
        return reply.code(400).send({
          ok: false,
          message: "No hay campos para actualizar",
        });
      }

      /*
       * Admin:
       * academia_id recibido se ignora.
       */
      if (academiaId && changes.academia_id !== undefined) {
        delete changes.academia_id;
      }

      /*
       * Regla Platino:
       * admin no puede asignar rol 3.
       */
      if (changes.rol_id !== undefined) {
        try {
          assertAdminCannotAssignSuperOr403(req, changes.rol_id, reply);
        } catch {
          return;
        }

        if ((reply as any).sent) {
          return;
        }
      }

      if (Object.keys(changes).length === 0) {
        return reply.code(400).send({
          ok: false,
          message: "No hay campos para actualizar",
        });
      }

      try {
        /*
         * Respuesta pública antes de añadir
         * ciphertexts e índices.
         */
        const publicChanges = {
          ...changes,
        };

        /*
         * Dual-write para todo PII modificado.
         */
        applyEncryptedMirrors(changes);

        if (typeof changes.password === "string") {
          changes.password = await argon2.hash(String(changes.password));
        }

        const setClauses: string[] = [];

        const values: any[] = [];

        if (changes.academia_id !== undefined) {
          setClauses.push("academia_id = ?");

          values.push(changes.academia_id);
        }

        /* -------------------------------------------------
           NOMBRE USUARIO
        ------------------------------------------------- */

        if (changes.nombre_usuario !== undefined) {
          setClauses.push("nombre_usuario = ?", "nombre_usuario_enc = ?", "nombre_usuario_idx = ?");

          values.push(changes.nombre_usuario, changes.nombre_usuario_enc, changes.nombre_usuario_idx);
        }

        /* -------------------------------------------------
           RUT
        ------------------------------------------------- */

        if (changes.rut_usuario !== undefined) {
          setClauses.push("rut_usuario = ?", "rut_usuario_enc = ?", "rut_usuario_idx = ?");

          values.push(changes.rut_usuario, changes.rut_usuario_enc, changes.rut_usuario_idx);
        }

        /* -------------------------------------------------
           EMAIL
        ------------------------------------------------- */

        if (changes.email !== undefined) {
          setClauses.push("email = ?", "email_enc = ?", "email_idx = ?");

          values.push(changes.email, changes.email_enc, changes.email_idx);
        }

        /* -------------------------------------------------
           PASSWORD
        ------------------------------------------------- */

        if (changes.password !== undefined) {
          setClauses.push("password = ?");

          values.push(changes.password);
        }

        /* -------------------------------------------------
           ROL
        ------------------------------------------------- */

        if (changes.rol_id !== undefined) {
          setClauses.push("rol_id = ?");

          values.push(changes.rol_id);
        }

        /* -------------------------------------------------
           ESTADO
        ------------------------------------------------- */

        if (changes.estado_id !== undefined) {
          setClauses.push("estado_id = ?");

          values.push(changes.estado_id);
        }

        if (setClauses.length === 0) {
          return reply.code(400).send({
            ok: false,
            message: "No hay campos para actualizar",
          });
        }

        values.push(id);

        /*
         * Scope adicional para rol 1.
         */
        let sql = `
          UPDATE usuarios

          SET
            ${setClauses.join(", ")}

          WHERE id = ?
        `;

        if (academiaId) {
          sql += " AND academia_id = ?";

          values.push(academiaId);
        }

        const [result]: any = await db.query(sql, values);

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,
            message: "No encontrado",
          });
        }

        /*
         * password jamás vuelve al cliente.
         */
        const { password, ...safe } = publicChanges;

        return reply.send({
          ok: true,

          updated: {
            id,
            ...safe,
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

        return reply.code(500).send({
          ok: false,

          message: "Error al actualizar usuario",

          detail: err?.message,
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

      const academiaId = getAcademiaIdOr403(req, reply);

      if ((reply as any).sent) {
        return;
      }

      /*
       * Admin:
       * no puede borrar fuera del tenant.
       */
      const okRow = await assertUserInAcademiaOr404(parsed.data.id, academiaId, reply);

      if (!okRow) {
        return;
      }

      /*
       * Regla Platino:
       * admin no puede borrar superadmin.
       */
      const okTarget = await assertTargetNotSuperOr403(parsed.data.id, req, reply);

      if (!okTarget) {
        return;
      }

      try {
        const args: any[] = [parsed.data.id];

        let sql = `
          DELETE FROM usuarios
          WHERE id = ?
        `;

        if (academiaId) {
          sql += " AND academia_id = ?";

          args.push(academiaId);
        }

        const [result]: any = await db.query(sql, args);

        if (Number(result?.affectedRows ?? 0) === 0) {
          return reply.code(404).send({
            ok: false,
            message: "No encontrado",
          });
        }

        return reply.send({
          ok: true,
          deleted: parsed.data.id,
        });
      } catch (err: any) {
        if (err?.errno === 1451 || err?.code === "ER_ROW_IS_REFERENCED_2") {
          return reply.code(409).send({
            ok: false,

            message: "No se puede eliminar: hay registros vinculados a este usuario.",

            detail: err?.sqlMessage ?? err?.message,
          });
        }

        return reply.code(500).send({
          ok: false,

          message: "Error al eliminar usuario",

          detail: err?.message,
        });
      }
    }
  );
}
