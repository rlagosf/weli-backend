// src/routers/convocatorias_historico.ts

import type {
  FastifyInstance,
  FastifyRequest,
  FastifyReply,
} from "fastify";

import { z } from "zod";

import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
} from "crypto";

import { db } from "../db";

import {
  requireAuth,
  requireRoles,
  getEffectiveAcademiaId,
} from "../middlewares/authz";

/* =========================================================
   ZOD SCHEMAS
========================================================= */

const CreateSchema = z.object({
  evento_id: z.coerce
    .number()
    .int()
    .positive(),

  convocatoria_id: z.coerce
    .number()
    .int()
    .positive(),

  fecha_generacion: z
    .string()
    .optional(),

  listado_base64: z
    .string()
    .min(10),
});

const IdParam = z.object({
  id: z.coerce
    .number()
    .int()
    .positive(),
});

const EventoConvParam = z.object({
  evento_id: z.coerce
    .number()
    .int()
    .positive(),

  convocatoria_id: z.coerce
    .number()
    .int()
    .positive(),
});

const PaginationQuery = z.object({
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
   CONFIGURACIÓN PDF / CIFRADO
========================================================= */

/*
 * AES-256-GCM:
 *
 * - Clave: 32 bytes / 256 bits
 * - IV: 12 bytes aleatorios por documento
 * - Auth Tag: 16 bytes
 *
 * La clave NO se almacena en MySQL.
 * Debe existir solamente en el entorno del backend.
 */

const ENCRYPTION_ALGORITHM =
  "aes-256-gcm";

const IV_LENGTH =
  12;

const AUTH_TAG_LENGTH =
  16;

/* =========================================================
   UTILS
========================================================= */

const stripDataUrlPrefix = (
  value: string
) => {
  const idx =
    value.indexOf(",");

  return (
    value.startsWith("data:") &&
    idx > -1
  )
    ? value.slice(idx + 1)
    : value;
};

const approxBytes = (
  base64: string
) =>
  Math.floor(
    (base64.length * 3) / 4
  );

const MAX_BYTES =
  Number(
    process.env.CONVOC_HIST_MAX_BYTES ||
      12 * 1024 * 1024
  );

const getErrorCode = (
  err: any
) =>
  err?.statusCode &&
  Number.isFinite(
    Number(
      err.statusCode
    )
  )
    ? Number(
        err.statusCode
      )
    : 500;

/* =========================================================
   OBTENER CLAVE AES
========================================================= */

function getEncryptionKey(): Buffer {
  const keyHex =
    String(
      process.env
        .CONVOCATORIAS_ENCRYPTION_KEY ??
        ""
    ).trim();

  /*
   * AES-256 necesita exactamente 32 bytes.
   *
   * 32 bytes expresados como HEX =
   * 64 caracteres hexadecimales.
   */
  if (
    !/^[0-9a-fA-F]{64}$/.test(
      keyHex
    )
  ) {
    throw new Error(
      "CONVOCATORIAS_ENCRYPTION_KEY no está configurada correctamente. Debe contener exactamente 64 caracteres hexadecimales."
    );
  }

  const key =
    Buffer.from(
      keyHex,
      "hex"
    );

  if (
    key.length !== 32
  ) {
    throw new Error(
      "CONVOCATORIAS_ENCRYPTION_KEY debe representar exactamente 32 bytes."
    );
  }

  return key;
}

/* =========================================================
   DETECTAR PDF LEGACY
========================================================= */

/*
 * Los registros antiguos fueron almacenados como:
 *
 * Base64(PDF)
 *
 * Por lo tanto, después de decodificarlos comienzan:
 *
 * %PDF-
 *
 * Esto permite mantener compatibilidad con todos los
 * registros creados antes de implementar AES-256-GCM.
 */

function isLegacyPdfBuffer(
  buffer: Buffer
): boolean {
  if (
    buffer.length < 5
  ) {
    return false;
  }

  return (
    buffer
      .subarray(
        0,
        5
      )
      .toString(
        "ascii"
      ) === "%PDF-"
  );
}

/* =========================================================
   CIFRAR PDF
========================================================= */

/*
 * Estructura binaria almacenada:
 *
 * ┌─────────────┬──────────────┬───────────────────────┐
 * │ IV 12 bytes │ TAG 16 bytes │ CIPHERTEXT N bytes    │
 * └─────────────┴──────────────┴───────────────────────┘
 *
 * Después:
 *
 * Buffer completo
 *      ↓
 * Base64
 *      ↓
 * listado_base64
 *
 * El Base64 resultante YA NO representa directamente
 * un archivo PDF.
 */

function encryptPdfBuffer(
  pdfBuffer: Buffer
): string {
  const key =
    getEncryptionKey();

  /*
   * IV completamente aleatorio y nuevo
   * para cada documento.
   */
  const iv =
    randomBytes(
      IV_LENGTH
    );

  const cipher =
    createCipheriv(
      ENCRYPTION_ALGORITHM,
      key,
      iv
    );

  const ciphertext =
    Buffer.concat([
      cipher.update(
        pdfBuffer
      ),

      cipher.final(),
    ]);

  /*
   * Tag de autenticación GCM.
   *
   * Permite detectar:
   * - corrupción
   * - modificaciones
   * - clave incorrecta
   */
  const authTag =
    cipher.getAuthTag();

  const payload =
    Buffer.concat([
      iv,
      authTag,
      ciphertext,
    ]);

  return payload.toString(
    "base64"
  );
}

/* =========================================================
   DESCIFRAR PDF
========================================================= */

function decryptPdfBuffer(
  encryptedBase64: string
): Buffer {
  const key =
    getEncryptionKey();

  const payload =
    Buffer.from(
      encryptedBase64,
      "base64"
    );

  /*
   * Debe contener como mínimo:
   *
   * 12 bytes IV
   * +
   * 16 bytes Auth Tag
   * +
   * al menos 1 byte ciphertext
   */
  if (
    payload.length <=
    IV_LENGTH +
      AUTH_TAG_LENGTH
  ) {
    throw new Error(
      "Documento cifrado inválido o incompleto."
    );
  }

  const iv =
    payload.subarray(
      0,
      IV_LENGTH
    );

  const authTag =
    payload.subarray(
      IV_LENGTH,
      IV_LENGTH +
        AUTH_TAG_LENGTH
    );

  const ciphertext =
    payload.subarray(
      IV_LENGTH +
        AUTH_TAG_LENGTH
    );

  const decipher =
    createDecipheriv(
      ENCRYPTION_ALGORITHM,
      key,
      iv
    );

  decipher.setAuthTag(
    authTag
  );

  try {
    return Buffer.concat([
      decipher.update(
        ciphertext
      ),

      decipher.final(),
    ]);
  } catch {
    /*
     * No exponemos información criptográfica
     * sensible en el error.
     */
    throw new Error(
      "No fue posible descifrar el documento."
    );
  }
}

/* =========================================================
   OBTENER PDF DESDE REGISTRO
========================================================= */

/*
 * Compatibilidad:
 *
 * REGISTRO ANTIGUO
 * Base64(PDF)
 *      ↓
 * detecta %PDF-
 *      ↓
 * devuelve directamente
 *
 *
 * REGISTRO NUEVO
 * Base64(AES-GCM(PDF))
 *      ↓
 * no comienza %PDF-
 *      ↓
 * decryptPdfBuffer()
 */

function getPdfBufferFromStoredValue(
  storedValue: string
): Buffer {
  const pure =
    stripDataUrlPrefix(
      storedValue
    );

  const decoded =
    Buffer.from(
      pure,
      "base64"
    );

  /*
   * Histórico anterior al cifrado.
   */
  if (
    isLegacyPdfBuffer(
      decoded
    )
  ) {
    return decoded;
  }

  /*
   * Histórico nuevo cifrado.
   */
  return decryptPdfBuffer(
    pure
  );
}

/* =========================================================
   USUARIO GENERADOR
========================================================= */

function getUserIdOrNull(
  req: any
): number | null {
  const auth =
    req?.auth;

  if (
    !auth ||
    typeof auth !== "object"
  ) {
    return null;
  }

  if (
    auth.type !== "user"
  ) {
    return null;
  }

  const id =
    Number(
      auth.user_id ?? 0
    );

  return (
    Number.isFinite(id) &&
    id > 0
  )
    ? id
    : null;
}

/* =========================================================
   VALIDAR EVENTO EN ACADEMIA
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

  if (
    !rows?.length
  ) {
    reply
      .code(403)
      .send({
        ok: false,

        message:
          "FORBIDDEN_EVENTO",
      });

    return false;
  }

  return true;
}

/* =========================================================
   VALIDAR CONVOCATORIA EN ACADEMIA
========================================================= */

async function assertConvocatoriaInAcademiaOrReply(
  evento_id: number,
  convocatoria_id: number,
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

       WHERE c.evento_id = ?
         AND c.convocatoria_id = ?
         AND c.academia_id = ?
         AND e.academia_id = ?

       LIMIT 1
      `,
      [
        evento_id,
        convocatoria_id,
        academia_id,
        academia_id,
      ]
    );

  if (
    !rows?.length
  ) {
    reply
      .code(404)
      .send({
        ok: false,

        message:
          "Convocatoria no encontrada",
      });

    return false;
  }

  return true;
}

/* =========================================================
   ROUTER
========================================================= */

export default async function convocatorias_historico(
  app: FastifyInstance
) {
  const canRead = [
    requireAuth,

    requireRoles([
      1,
      2,
      3,
    ]),
  ];

  const canWrite = [
    requireAuth,

    requireRoles([
      1,
      3,
    ]),
  ];

  /* =======================================================
     HEALTH
  ======================================================= */

  app.get(
    "/health",
    {
      preHandler:
        canRead,
    },
    async () => ({
      module:
        "convocatorias_historico",

      status:
        "ready",

      timestamp:
        new Date()
          .toISOString(),
    })
  );

  /* =======================================================
     LISTAR
  ======================================================= */

  app.get(
    "/",
    {
      preHandler:
        canRead,
    },
    async (
      req: FastifyRequest,
      reply: FastifyReply
    ) => {
      try {
        const parsed =
          PaginationQuery.safeParse(
            req.query
          );

        const page =
          parsed.success &&
          parsed.data.page
            ? Number(
                parsed.data.page
              )
            : 1;

        const size =
          parsed.success &&
          parsed.data.pageSize
            ? Number(
                parsed.data
                  .pageSize
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
              size,
              1
            ),
            200
          );

        const offset =
          (
            safePage -
            1
          ) * limit;

        const academia_id =
          getEffectiveAcademiaId(
            req
          );

        const [rows]: any =
          await db.query(
            `
            SELECT
              h.id,
              h.academia_id,
              h.evento_id,
              h.convocatoria_id,
              h.fecha_generacion,
              h.generado_por

              FROM convocatorias_historico h

              INNER JOIN eventos e
                ON e.id = h.evento_id

             WHERE h.academia_id = ?
               AND e.academia_id = ?

             ORDER BY
               h.fecha_generacion DESC,
               h.id DESC

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

        return reply.send({
          ok: true,

          items:
            rows,

          page:
            safePage,

          pageSize:
            limit,

          academia_id,
        });
      } catch (
        err: any
      ) {
        return reply
          .code(
            getErrorCode(
              err
            )
          )
          .send({
            ok: false,

            message:
              "Error al listar",

            error:
              err?.message,
          });
      }
    }
  );

  /* =======================================================
     OBTENER POR EVENTO + CONVOCATORIA
  ======================================================= */

  app.get(
    "/evento/:evento_id/convocatoria/:convocatoria_id",
    {
      preHandler:
        canRead,
    },
    async (
      req: FastifyRequest,
      reply: FastifyReply
    ) => {
      const parsed =
        EventoConvParam.safeParse(
          req.params
        );

      if (
        !parsed.success
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
        parsed.data;

      try {
        const academia_id =
          getEffectiveAcademiaId(
            req
          );

        const [rows]: any =
          await db.query(
            `
            SELECT
              h.id,
              h.academia_id,
              h.evento_id,
              h.convocatoria_id,
              h.fecha_generacion,
              h.generado_por

              FROM convocatorias_historico h

              INNER JOIN eventos e
                ON e.id = h.evento_id

             WHERE h.evento_id = ?
               AND h.convocatoria_id = ?
               AND h.academia_id = ?
               AND e.academia_id = ?

             ORDER BY
               h.fecha_generacion DESC,
               h.id DESC
            `,
            [
              evento_id,
              convocatoria_id,
              academia_id,
              academia_id,
            ]
          );

        return reply.send({
          ok: true,

          items:
            rows,

          academia_id,
        });
      } catch (
        err: any
      ) {
        return reply
          .code(
            getErrorCode(
              err
            )
          )
          .send({
            ok: false,

            message:
              "Error al obtener registros del evento",

            error:
              err?.message,
          });
      }
    }
  );

  /* =======================================================
     VER PDF
  ======================================================= */

  app.get(
    "/ver/:id",
    {
      preHandler:
        canRead,
    },
    async (
      req: FastifyRequest,
      reply: FastifyReply
    ) => {
      const parsed =
        IdParam.safeParse(
          req.params
        );

      if (
        !parsed.success
      ) {
        return reply
          .code(400)
          .send({
            ok: false,

            message:
              "ID inválido",
          });
      }

      const {
        id,
      } =
        parsed.data;

      try {
        const academia_id =
          getEffectiveAcademiaId(
            req
          );

        const [rows]: any =
          await db.query(
            `
            SELECT
              h.listado_base64

              FROM convocatorias_historico h

              INNER JOIN eventos e
                ON e.id = h.evento_id

             WHERE h.id = ?
               AND h.academia_id = ?
               AND e.academia_id = ?

             LIMIT 1
            `,
            [
              id,
              academia_id,
              academia_id,
            ]
          );

        if (
          !rows?.length
        ) {
          return reply
            .code(404)
            .send({
              ok: false,

              message:
                "No encontrado",
            });
        }

        /*
         * Automáticamente:
         *
         * - devuelve PDF legacy
         * - o descifra PDF AES-256-GCM
         */
        const buffer =
          getPdfBufferFromStoredValue(
            String(
              rows[0]
                .listado_base64 ??
                ""
            )
          );

        /*
         * Validación defensiva después
         * de descifrar.
         */
        if (
          !isLegacyPdfBuffer(
            buffer
          )
        ) {
          throw new Error(
            "El contenido recuperado no corresponde a un PDF válido."
          );
        }

        reply.header(
          "Content-Type",
          "application/pdf"
        );

        reply.header(
          "Content-Disposition",
          `inline; filename="convocatoria_${id}.pdf"`
        );

        return reply.send(
          buffer
        );
      } catch (
        err: any
      ) {
        return reply
          .code(
            getErrorCode(
              err
            )
          )
          .send({
            ok: false,

            message:
              "Error al generar PDF",

            error:
              err?.message,
          });
      }
    }
  );

  /* =======================================================
     OBTENER POR ID
  ======================================================= */

  app.get(
    "/:id",
    {
      preHandler:
        canRead,
    },
    async (
      req: FastifyRequest,
      reply: FastifyReply
    ) => {
      const parsed =
        IdParam.safeParse(
          req.params
        );

      if (
        !parsed.success
      ) {
        return reply
          .code(400)
          .send({
            ok: false,

            message:
              "ID inválido",
          });
      }

      const {
        id,
      } =
        parsed.data;

      try {
        const academia_id =
          getEffectiveAcademiaId(
            req
          );

        /*
         * Se conserva exactamente
         * la consulta existente.
         */
        const [rows]: any =
          await db.query(
            `
            SELECT h.*

              FROM convocatorias_historico h

              INNER JOIN eventos e
                ON e.id = h.evento_id

             WHERE h.id = ?
               AND h.academia_id = ?
               AND e.academia_id = ?

             LIMIT 1
            `,
            [
              id,
              academia_id,
              academia_id,
            ]
          );

        if (
          !rows?.length
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

          item:
            rows[0],

          academia_id,
        });
      } catch (
        err: any
      ) {
        return reply
          .code(
            getErrorCode(
              err
            )
          )
          .send({
            ok: false,

            message:
              "Error al obtener registro",

            error:
              err?.message,
          });
      }
    }
  );

  /* =======================================================
     CREAR HISTÓRICO
  ======================================================= */

  app.post(
    "/",
    {
      preHandler:
        canWrite,
    },
    async (
      req: FastifyRequest,
      reply: FastifyReply
    ) => {
      const parsed =
        CreateSchema.safeParse(
          req.body
        );

      if (
        !parsed.success
      ) {
        return reply
          .code(400)
          .send({
            ok: false,

            message:
              "Payload inválido",

            errors:
              parsed.error
                .flatten(),
          });
      }

      const {
        evento_id,
        convocatoria_id,
        listado_base64,
      } =
        parsed.data;

      const {
        fecha_generacion,
      } =
        parsed.data;

      try {
        /* ===============================================
           ACADEMIA EFECTIVA
        =============================================== */

        const academia_id =
          getEffectiveAcademiaId(
            req
          );

        /* ===============================================
           VALIDAR EVENTO
        =============================================== */

        const okEvento =
          await assertEventoInAcademiaOrReply(
            evento_id,
            academia_id,
            reply
          );

        if (
          !okEvento
        ) {
          return;
        }

        /* ===============================================
           VALIDAR CONVOCATORIA
        =============================================== */

        const okConvocatoria =
          await assertConvocatoriaInAcademiaOrReply(
            evento_id,
            convocatoria_id,
            academia_id,
            reply
          );

        if (
          !okConvocatoria
        ) {
          return;
        }

        /* ===============================================
           PDF BASE64 RECIBIDO
        =============================================== */

        const pure =
          stripDataUrlPrefix(
            listado_base64
          );

        /*
         * Se mantiene el mismo límite
         * utilizado originalmente.
         */
        const bytes =
          approxBytes(
            pure
          );

        if (
          bytes >
          MAX_BYTES
        ) {
          return reply
            .code(413)
            .send({
              ok: false,

              message:
                `El PDF excede el límite permitido (${Math.floor(
                  MAX_BYTES /
                    (
                      1024 *
                      1024
                    )
                )} MB).`,
            });
        }

        /* ===============================================
           BASE64 -> PDF BUFFER
        =============================================== */

        const pdfBuffer =
          Buffer.from(
            pure,
            "base64"
          );

        if (
          !pdfBuffer.length
        ) {
          return reply
            .code(400)
            .send({
              ok: false,

              message:
                "PDF vacío o inválido",
            });
        }

        /* ===============================================
           CIFRAR PDF

           IMPORTANTE:

           Lo que se almacenará en listado_base64
           ya NO será Base64(PDF).

           Será:

           Base64(
             IV +
             AUTH_TAG +
             AES_CIPHERTEXT
           )
        =============================================== */

        const encryptedBase64 =
          encryptPdfBuffer(
            pdfBuffer
          );

        /* ===============================================
           FECHA
        =============================================== */

        let fechaMySQL:
          | string
          | null =
          null;

        if (
          fecha_generacion
        ) {
          const date =
            new Date(
              fecha_generacion
            );

          if (
            !Number.isNaN(
              date.getTime()
            )
          ) {
            fechaMySQL =
              date
                .toISOString()
                .slice(
                  0,
                  19
                )
                .replace(
                  "T",
                  " "
                );
          }
        }

        /* ===============================================
           USUARIO GENERADOR
        =============================================== */

        const generado_por =
          getUserIdOrNull(
            req
          );

        /* ===============================================
           INSERT

           Se conserva:
           - academia_id
           - evento_id
           - convocatoria_id
           - fecha_generacion
           - listado_base64
           - generado_por

           ÚNICAMENTE cambia el contenido almacenado
           en listado_base64.
        =============================================== */

        const sql =
          fechaMySQL
            ? `
              INSERT INTO convocatorias_historico
              (
                academia_id,
                evento_id,
                convocatoria_id,
                fecha_generacion,
                listado_base64,
                generado_por
              )
              VALUES (?, ?, ?, ?, ?, ?)
            `
            : `
              INSERT INTO convocatorias_historico
              (
                academia_id,
                evento_id,
                convocatoria_id,
                fecha_generacion,
                listado_base64,
                generado_por
              )
              VALUES (?, ?, ?, NOW(), ?, ?)
            `;

        const params =
          fechaMySQL
            ? [
                academia_id,
                evento_id,
                convocatoria_id,
                fechaMySQL,

                /*
                 * Antes:
                 *
                 * pure
                 *
                 * Ahora:
                 *
                 * encryptedBase64
                 */
                encryptedBase64,

                generado_por,
              ]
            : [
                academia_id,
                evento_id,
                convocatoria_id,

                encryptedBase64,

                generado_por,
              ];

        const [result]: any =
          await db.query(
            sql,
            params
          );

        return reply
          .code(201)
          .send({
            ok: true,

            id:
              result.insertId,

            evento_id,

            convocatoria_id,

            academia_id,

            fecha_generacion:
              fechaMySQL ??
              new Date()
                .toISOString(),
          });
      } catch (
        err: any
      ) {
        return reply
          .code(
            getErrorCode(
              err
            )
          )
          .send({
            ok: false,

            message:
              "Error al crear registro",

            error:
              err?.message,
          });
      }
    }
  );
}