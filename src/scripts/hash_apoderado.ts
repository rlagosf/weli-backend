// src/scripts/hash_apoderado.ts

import * as argon2 from "@node-rs/argon2";

import { getDb } from "../db";

import {
  blindIndex,
  decryptNullable,
  encryptNullable,
  encryptRut,
  normalizeRut,
  rutBlindIndex,
  validateCryptoConfiguration,
} from "../services/crypto";

type EnsureResult =
  | {
      ok: true;
      created: boolean;
      rut_apoderado: string;
      nombre_apoderado: string;
    }
  | {
      ok: false;
      created: false;
      message: string;
    };

/* =========================================================
   NORMALIZACIONES
========================================================= */

function normalizeRutBody(rutLike: string) {
  return normalizeRut(rutLike);
}

function normalizeNombre(nombreLike?: string) {
  return String(nombreLike ?? "")
    .trim()
    .replace(/\s+/g, " ");
}

function normalizeNombreIndex(nombreLike?: string) {
  return normalizeNombre(nombreLike).toLowerCase();
}

/* =========================================================
   HELPERS DE LECTURA SEGURA
========================================================= */

function decryptNombreOrLegacy(encrypted: unknown, legacy: unknown): string {
  if (encrypted !== null && encrypted !== undefined && String(encrypted).trim() !== "") {
    const value = decryptNullable(String(encrypted));

    return normalizeNombre(value ?? undefined);
  }

  return normalizeNombre(legacy == null ? undefined : String(legacy));
}

/* =========================================================
   ENSURE APODERADO AUTH
========================================================= */

/**
 * Garantiza una única identidad de apoderado por RUT.
 *
 * Reglas:
 *
 * - No pisa password_hash si el RUT ya existe.
 * - La búsqueda principal se realiza mediante rut_apoderado_idx.
 * - Si el apoderado ya existe, devuelve el nombre canónico guardado.
 * - Si existe una credencial histórica sin nombre, completa el nombre.
 * - Si no existe, crea credencial + nombre.
 * - must_change_password = 1 sólo al crear una credencial nueva.
 * - password_hash continúa siendo Argon2 y nunca se cifra con AES.
 *
 * Fase transitoria:
 *
 * - mantiene las columnas legacy;
 * - sincroniza rut_apoderado_enc;
 * - sincroniza rut_apoderado_idx;
 * - sincroniza nombre_apoderado_enc;
 * - sincroniza nombre_apoderado_idx.
 *
 * Regla WELI para RUT:
 *
 * - cuerpo numérico;
 * - sin puntos;
 * - sin guion;
 * - sin DV;
 * - 7 u 8 dígitos.
 */
export async function ensureApoderadoAuth({
  rut_apoderado,
  nombre_apoderado,
  provisionalPlainPassword = process.env.APODERADO_PROVISIONAL_PASSWORD || "RAFC2025!",
}: {
  rut_apoderado: string;
  nombre_apoderado?: string;
  provisionalPlainPassword?: string;
}): Promise<EnsureResult> {
  /*
   * Fail-fast.
   *
   * Este helper no debe operar si las claves
   * criptográficas no están configuradas correctamente.
   */
  validateCryptoConfiguration();

  let rutNormalizado: string;

  try {
    rutNormalizado = normalizeRutBody(rut_apoderado);
  } catch {
    return {
      ok: false,
      created: false,
      message: "RUT_APODERADO_INVALID",
    };
  }

  const nombre = normalizeNombre(nombre_apoderado);

  if (nombre && nombre.length > 120) {
    return {
      ok: false,
      created: false,
      message: "NOMBRE_APODERADO_TOO_LONG",
    };
  }

  const db = getDb();

  /*
   * Blind index determinístico.
   *
   * Ya no usamos rut_apoderado plaintext
   * como clave primaria de búsqueda lógica.
   */
  const rutIdx = rutBlindIndex(rutNormalizado);

  /* =======================================================
     1. BUSCAR IDENTIDAD EXISTENTE
  ======================================================= */

  const [existRows] = await db.query<any[]>(
    `
        SELECT
          apoderado_id,

          rut_apoderado,
          rut_apoderado_enc,
          rut_apoderado_idx,

          nombre_apoderado,
          nombre_apoderado_enc,
          nombre_apoderado_idx

        FROM apoderados_auth

        WHERE rut_apoderado_idx = ?

        LIMIT 1
      `,
    [rutIdx]
  );

  if (existRows?.length) {
    const actual = existRows[0];

    const nombreCanonico = decryptNombreOrLegacy(actual?.nombre_apoderado_enc, actual?.nombre_apoderado);

    /* -----------------------------------------------------
       REGISTRO HISTÓRICO SIN NOMBRE
    ----------------------------------------------------- */

    if (!nombreCanonico) {
      if (!nombre) {
        return {
          ok: false,
          created: false,
          message: "NOMBRE_APODERADO_REQUIRED",
        };
      }

      const nombreEnc = encryptNullable(nombre);

      const nombreIdx = blindIndex(normalizeNombreIndex(nombre));

      /*
       * Dual-write.
       *
       * Conservamos nombre_apoderado legacy
       * sólo durante esta fase de transición.
       */
      await db.query(
        `
          UPDATE apoderados_auth

          SET
            nombre_apoderado = ?,
            nombre_apoderado_enc = ?,
            nombre_apoderado_idx = ?,
            updated_at = NOW()

          WHERE apoderado_id = ?

            AND (
              nombre_apoderado_enc IS NULL
              OR TRIM(nombre_apoderado_enc) = ''
            )

          LIMIT 1
        `,
        [nombre, nombreEnc, nombreIdx, Number(actual.apoderado_id)]
      );

      return {
        ok: true,
        created: false,
        rut_apoderado: rutNormalizado,
        nombre_apoderado: nombre,
      };
    }

    /* -----------------------------------------------------
       IDENTIDAD EXISTENTE
    ----------------------------------------------------- */

    /*
     * Protección adicional:
     *
     * Si el registro histórico existía pero alguno de los
     * mirrors criptográficos todavía estuviera incompleto,
     * lo reparamos sin tocar password_hash.
     */
    const repairAssignments: string[] = [];

    const repairValues: unknown[] = [];

    if (
      actual?.rut_apoderado_enc === null ||
      actual?.rut_apoderado_enc === undefined ||
      String(actual.rut_apoderado_enc).trim() === ""
    ) {
      repairAssignments.push("rut_apoderado_enc = ?");

      repairValues.push(encryptRut(rutNormalizado));
    }

    if (
      actual?.rut_apoderado_idx === null ||
      actual?.rut_apoderado_idx === undefined ||
      String(actual.rut_apoderado_idx).trim() === ""
    ) {
      repairAssignments.push("rut_apoderado_idx = ?");

      repairValues.push(rutIdx);
    }

    if (
      actual?.nombre_apoderado_enc === null ||
      actual?.nombre_apoderado_enc === undefined ||
      String(actual.nombre_apoderado_enc).trim() === ""
    ) {
      repairAssignments.push("nombre_apoderado_enc = ?");

      repairValues.push(encryptNullable(nombreCanonico));
    }

    if (
      actual?.nombre_apoderado_idx === null ||
      actual?.nombre_apoderado_idx === undefined ||
      String(actual.nombre_apoderado_idx).trim() === ""
    ) {
      repairAssignments.push("nombre_apoderado_idx = ?");

      repairValues.push(blindIndex(normalizeNombreIndex(nombreCanonico)));
    }

    if (repairAssignments.length > 0) {
      repairValues.push(Number(actual.apoderado_id));

      await db.query(
        `
          UPDATE apoderados_auth

          SET
            ${repairAssignments.join(",\n            ")},
            updated_at = NOW()

          WHERE apoderado_id = ?

          LIMIT 1
        `,
        repairValues
      );
    }

    /*
     * RUT existente:
     *
     * el nombre almacenado manda.
     */
    return {
      ok: true,
      created: false,
      rut_apoderado: rutNormalizado,
      nombre_apoderado: nombreCanonico,
    };
  }

  /* =======================================================
     2. CREAR NUEVA IDENTIDAD
  ======================================================= */

  if (!nombre) {
    return {
      ok: false,
      created: false,
      message: "NOMBRE_APODERADO_REQUIRED",
    };
  }

  /*
   * Hash irreversible.
   *
   * No usar encryptField / AES para contraseña.
   */
  const hash = await argon2.hash(provisionalPlainPassword);

  const rutEnc = encryptRut(rutNormalizado);

  const nombreEnc = encryptNullable(nombre);

  const nombreIdx = blindIndex(normalizeNombreIndex(nombre));

  try {
    await db.query(
      `
        INSERT INTO apoderados_auth
        (
          rut_apoderado,
          rut_apoderado_enc,
          rut_apoderado_idx,

          nombre_apoderado,
          nombre_apoderado_enc,
          nombre_apoderado_idx,

          password_hash,

          must_change_password,
          estado_id,

          created_at,
          updated_at
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

          1,
          1,

          NOW(),
          NOW()
        )
      `,
      [rutNormalizado, rutEnc, rutIdx, nombre, nombreEnc, nombreIdx, hash]
    );

    return {
      ok: true,
      created: true,
      rut_apoderado: rutNormalizado,
      nombre_apoderado: nombre,
    };
  } catch (error: any) {
    /* -----------------------------------------------------
       CONCURRENCIA
    ----------------------------------------------------- */

    if (error?.errno === 1062 || error?.code === "ER_DUP_ENTRY") {
      /*
       * Dos solicitudes pueden haber intentado crear
       * el mismo RUT simultáneamente.
       *
       * Reconsultamos por blind index.
       */
      const [rows] = await db.query<any[]>(
        `
            SELECT
              apoderado_id,
              rut_apoderado_enc,
              nombre_apoderado,
              nombre_apoderado_enc

            FROM apoderados_auth

            WHERE rut_apoderado_idx = ?

            LIMIT 1
          `,
        [rutIdx]
      );

      if (rows?.length) {
        const canonico = decryptNombreOrLegacy(rows[0]?.nombre_apoderado_enc, rows[0]?.nombre_apoderado);

        if (canonico) {
          return {
            ok: true,
            created: false,
            rut_apoderado: rutNormalizado,
            nombre_apoderado: canonico,
          };
        }
      }
    }

    throw error;
  }
}

/*
 * NO dejar hashes reales ni sentencias manuales
 * de recuperación dentro del archivo productivo.
 *
 * Si alguna vez necesitas resetear una contraseña,
 * conviene hacerlo mediante un script controlado
 * separado y no mediante SQL comentado aquí.
 */
