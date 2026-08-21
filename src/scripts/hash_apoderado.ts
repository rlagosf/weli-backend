// src/scripts/hash_apoderado.ts
import * as argon2 from "@node-rs/argon2";
import { getDb } from "../db";

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

function normalizeRut8(rutLike: string) {
  return String(rutLike ?? "")
    .trim()
    .replace(/[^\d]/g, "");
}

function normalizeNombre(nombreLike?: string) {
  return String(nombreLike ?? "")
    .trim()
    .replace(/\s+/g, " ");
}

/**
 * Garantiza una única identidad de apoderado por RUT.
 *
 * Reglas:
 * - No pisa password_hash si el RUT ya existe.
 * - Si el apoderado ya existe, devuelve el nombre canónico guardado.
 * - Si existe una credencial histórica sin nombre, completa el nombre
 *   con el recibido en esta operación.
 * - Si no existe, crea credencial + nombre.
 * - must_change_password = 1 solo al crear una credencial nueva.
 *
 * Importante:
 * El comportamiento del RUT se mantiene como estaba:
 * 8 dígitos sin DV.
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
  const rut8 = normalizeRut8(rut_apoderado);
  const nombre = normalizeNombre(nombre_apoderado);

  if (!/^\d{8}$/.test(rut8)) {
    return {
      ok: false,
      created: false,
      message: "RUT_APODERADO_INVALID",
    };
  }

  if (nombre && nombre.length > 120) {
    return {
      ok: false,
      created: false,
      message: "NOMBRE_APODERADO_TOO_LONG",
    };
  }

  const db = getDb();

  // 1) Si ya existe, jamás se toca la contraseña.
  const [existRows] = await db.query<any[]>(
    `SELECT
        rut_apoderado,
        nombre_apoderado
     FROM apoderados_auth
     WHERE rut_apoderado = ?
     LIMIT 1`,
    [rut8]
  );

  if (existRows?.length) {
    const nombreCanonico = normalizeNombre(existRows[0]?.nombre_apoderado);

    // Registro histórico anterior a la nueva columna:
    // conserva credenciales y completa solamente el nombre faltante.
    if (!nombreCanonico) {
      if (!nombre) {
        return {
          ok: false,
          created: false,
          message: "NOMBRE_APODERADO_REQUIRED",
        };
      }

      await db.query(
        `UPDATE apoderados_auth
         SET nombre_apoderado = ?,
             updated_at = NOW()
         WHERE rut_apoderado = ?
           AND (nombre_apoderado IS NULL OR TRIM(nombre_apoderado) = '')`,
        [nombre, rut8]
      );

      return {
        ok: true,
        created: false,
        rut_apoderado: rut8,
        nombre_apoderado: nombre,
      };
    }

    // RUT existente: el nombre guardado manda.
    return {
      ok: true,
      created: false,
      rut_apoderado: rut8,
      nombre_apoderado: nombreCanonico,
    };
  }

  // 2) No existe: para crear identidad nueva necesitamos nombre real.
  if (!nombre) {
    return {
      ok: false,
      created: false,
      message: "NOMBRE_APODERADO_REQUIRED",
    };
  }

  const hash = await argon2.hash(provisionalPlainPassword);

  try {
    await db.query(
      `INSERT INTO apoderados_auth
        (
          rut_apoderado,
          nombre_apoderado,
          password_hash,
          must_change_password,
          estado_id,
          created_at,
          updated_at
        )
       VALUES
        (?, ?, ?, 1, 1, NOW(), NOW())`,
      [rut8, nombre, hash]
    );

    return {
      ok: true,
      created: true,
      rut_apoderado: rut8,
      nombre_apoderado: nombre,
    };
  } catch (error: any) {
    // Protección frente a dos altas simultáneas del mismo RUT.
    if (error?.errno === 1062 || error?.code === "ER_DUP_ENTRY") {
      const [rows] = await db.query<any[]>(
        `SELECT rut_apoderado, nombre_apoderado
         FROM apoderados_auth
         WHERE rut_apoderado = ?
         LIMIT 1`,
        [rut8]
      );

      const canonico = normalizeNombre(rows?.[0]?.nombre_apoderado);

      if (canonico) {
        return {
          ok: true,
          created: false,
          rut_apoderado: rut8,
          nombre_apoderado: canonico,
        };
      }
    }

    throw error;
  }
}

// UPDATE apoderados_auth
// SET password_hash = '$argon2id$v=19$m=19456,t=2,p=1$GHvmaHaLIOy8qlKfedgaOA$VTTKy9Orp7AV3Ymq84ZVR/I1B7iqcgl6ZxyqxphodMs',
//     must_change_password = 1,
//     updated_at = NOW()
// WHERE rut_apoderado = '16978094';