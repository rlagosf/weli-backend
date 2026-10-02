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

function normalizeRutBody(rutLike: string): string {
  return normalizeRut(rutLike);
}

function normalizeNombre(nombreLike?: string): string {
  return String(nombreLike ?? "")
    .trim()
    .replace(/\s+/g, " ");
}

function normalizeNombreIndex(nombreLike?: string): string {
  return normalizeNombre(nombreLike).toLowerCase();
}

/* =========================================================
   HELPERS
========================================================= */

function decryptNombre(encrypted: unknown): string {
  if (encrypted === null || encrypted === undefined || String(encrypted).trim() === "") {
    return "";
  }

  const value = decryptNullable(String(encrypted));

  return normalizeNombre(value ?? undefined);
}

/* =========================================================
   ENSURE APODERADO AUTH
========================================================= */

/**
 * Garantiza una única identidad de apoderado por RUT.
 *
 * Reglas:
 *
 * - No modifica password_hash si la identidad ya existe.
 * - La búsqueda se realiza exclusivamente mediante rut_apoderado_idx.
 * - El RUT nunca se busca ni almacena en plaintext.
 * - El nombre nunca se almacena en plaintext.
 * - Si el apoderado existe, devuelve su nombre canónico descifrado.
 * - Si existe una identidad histórica sin nombre cifrado, permite
 *   completar únicamente el nombre, sin alterar sus credenciales.
 * - Si no existe, crea la identidad y sus credenciales iniciales.
 * - must_change_password = 1 sólo al crear una nueva identidad.
 * - password_hash continúa siendo Argon2.
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
   * Fail-fast:
   *
   * Si las claves de cifrado/índice no están correctamente
   * configuradas, este helper no debe operar.
   */
  validateCryptoConfiguration();

  /* =======================================================
     NORMALIZAR RUT
  ======================================================= */

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

  /*
   * Defensa adicional.
   *
   * Aunque normalizeRut() ya normalice el valor, mantenemos
   * explícita la regla funcional de WELI.
   */
  if (!/^\d{7,8}$/.test(rutNormalizado)) {
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
   * Blind index determinístico para búsquedas exactas.
   *
   * El ciphertext nunca se utiliza como clave de búsqueda.
   */
  const rutIdx = rutBlindIndex(rutNormalizado);

  /* =======================================================
     1. BUSCAR IDENTIDAD EXISTENTE
  ======================================================= */

  const [existRows] = await db.query<any[]>(
    `
      SELECT
        apoderado_id,
        rut_apoderado_enc,
        rut_apoderado_idx,
        nombre_apoderado_enc,
        nombre_apoderado_idx,
        password_hash,
        must_change_password,
        estado_id

      FROM apoderados_auth

      WHERE rut_apoderado_idx = ?

      LIMIT 1
    `,
    [rutIdx]
  );

  if (existRows?.length) {
    const actual = existRows[0];

    /*
     * Nunca tocamos password_hash para una identidad existente.
     */
    const nombreCanonico = decryptNombre(actual?.nombre_apoderado_enc);

    /* -----------------------------------------------------
       REGISTRO EXISTENTE SIN NOMBRE CIFRADO
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

      await db.query(
        `
          UPDATE apoderados_auth

          SET
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
        [nombreEnc, nombreIdx, Number(actual.apoderado_id)]
      );

      return {
        ok: true,
        created: false,
        rut_apoderado: rutNormalizado,
        nombre_apoderado: nombre,
      };
    }

    /* -----------------------------------------------------
       REPARACIÓN DE MIRRORS CRIPTOGRÁFICOS
    ----------------------------------------------------- */

    const repairAssignments: string[] = [];
    const repairValues: unknown[] = [];

    /*
     * En condiciones normales rut_apoderado_idx ya existe,
     * porque precisamente encontramos el registro mediante él.
     *
     * Se conserva la validación defensiva para mantener
     * consistencia del registro.
     */
    if (
      actual?.rut_apoderado_enc === null ||
      actual?.rut_apoderado_enc === undefined ||
      String(actual.rut_apoderado_enc).trim() === ""
    ) {
      repairAssignments.push("rut_apoderado_enc = ?");
      repairValues.push(encryptRut(rutNormalizado));
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
     * La identidad existente siempre manda.
     *
     * Aunque el frontend envíe otro nombre para el mismo RUT,
     * se devuelve el nombre canónico previamente registrado.
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
   * Contraseña provisional:
   *
   * Argon2 es irreversible.
   * Nunca se cifra con AES.
   */
  const hash = await argon2.hash(provisionalPlainPassword);

  /*
   * Datos privados.
   */
  const rutEnc = encryptRut(rutNormalizado);

  const nombreEnc = encryptNullable(nombre);

  /*
   * Índice determinístico del nombre.
   *
   * Permite mantener compatibilidad con funcionalidades
   * futuras de comparación exacta sin revelar el plaintext.
   */
  const nombreIdx = blindIndex(normalizeNombreIndex(nombre));

  try {
    await db.query(
      `
        INSERT INTO apoderados_auth
        (
          rut_apoderado_enc,
          rut_apoderado_idx,

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

          1,
          1,

          NOW(),
          NOW()
        )
      `,
      [rutEnc, rutIdx, nombreEnc, nombreIdx, hash]
    );

    return {
      ok: true,
      created: true,
      rut_apoderado: rutNormalizado,
      nombre_apoderado: nombre,
    };
  } catch (error: any) {
    /* -----------------------------------------------------
       CONCURRENCIA / DUPLICADO
    ----------------------------------------------------- */

    if (error?.errno === 1062 || error?.code === "ER_DUP_ENTRY") {
      /*
       * Dos solicitudes podrían intentar crear el mismo
       * apoderado simultáneamente.
       *
       * Reconsultamos por el blind index canónico.
       */
      const [rows] = await db.query<any[]>(
        `
          SELECT
            apoderado_id,
            rut_apoderado_enc,
            rut_apoderado_idx,
            nombre_apoderado_enc,
            nombre_apoderado_idx

          FROM apoderados_auth

          WHERE rut_apoderado_idx = ?

          LIMIT 1
        `,
        [rutIdx]
      );

      if (rows?.length) {
        const canonico = decryptNombre(rows[0]?.nombre_apoderado_enc);

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

    /*
     * Cualquier otro error debe llegar al router.
     *
     * jugadores.ts devolverá entonces el detalle correspondiente
     * sin esconder errores reales de infraestructura/esquema.
     */
    throw error;
  }
}

/*
 * Seguridad:
 *
 * No dejar hashes reales, RUT, nombres ni sentencias manuales
 * de recuperación dentro del archivo productivo.
 *
 * Los resets de contraseña deben implementarse mediante
 * un flujo o script administrativo controlado.
 */
