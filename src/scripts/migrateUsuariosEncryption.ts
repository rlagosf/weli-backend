// src/scripts/migrateUsuariosEncryption.ts

import {
  blindIndex,
  cryptoSelfTest,
  encryptNullable,
  encryptRut,
  normalizeRut,
  rutBlindIndex,
  validateCryptoConfiguration,
} from "../services/crypto";

import {
  getDb,
  initDb,
  withTransaction,
} from "../db";

/* =========================================================
   TIPOS
========================================================= */

type NullableString = string | null;

type UsuarioMigrationRow = {
  id: number;

  nombre_usuario: NullableString;
  nombre_usuario_enc: NullableString;
  nombre_usuario_idx: NullableString;

  rut_usuario: number | string | null;
  rut_usuario_enc: NullableString;
  rut_usuario_idx: NullableString;

  email: NullableString;
  email_enc: NullableString;
  email_idx: NullableString;
};

type MigrationStats = {
  total: number;
  updated: number;
  alreadyMigrated: number;
  withoutSensitiveData: number;
};

/* =========================================================
   HELPERS
========================================================= */

function hasValue(value: unknown): boolean {
  if (value === null || value === undefined) {
    return false;
  }

  return String(value).trim().length > 0;
}

function targetMissing(value: unknown): boolean {
  return !hasValue(value);
}

/* =========================================================
   NORMALIZACIONES
========================================================= */

/**
 * Nombre de usuario canónico para blind index.
 *
 * Se normaliza:
 * - trim
 * - lowercase
 *
 * Ejemplo:
 *
 * AdminPrincipal
 *
 * ↓
 *
 * adminprincipal
 */
function normalizeUsername(value: unknown): string {
  const normalized = String(value ?? "")
    .trim()
    .toLowerCase();

  if (!normalized) {
    throw new Error(
      "El nombre de usuario no puede estar vacío."
    );
  }

  return normalized;
}

/**
 * Email canónico para blind index.
 *
 * Se normaliza:
 * - trim
 * - lowercase
 */
function normalizeEmail(value: unknown): string {
  const normalized = String(value ?? "")
    .trim()
    .toLowerCase();

  if (!normalized) {
    throw new Error(
      "El email no puede estar vacío."
    );
  }

  return normalized;
}

/* =========================================================
   DETECCIÓN DE DATOS
========================================================= */

function rowHasSensitiveSource(
  row: UsuarioMigrationRow
): boolean {
  return (
    hasValue(row.nombre_usuario) ||
    row.rut_usuario !== null ||
    hasValue(row.email)
  );
}

function rowNeedsMigration(
  row: UsuarioMigrationRow
): boolean {
  if (
    hasValue(row.nombre_usuario) &&
    (
      targetMissing(row.nombre_usuario_enc) ||
      targetMissing(row.nombre_usuario_idx)
    )
  ) {
    return true;
  }

  if (
    row.rut_usuario !== null &&
    (
      targetMissing(row.rut_usuario_enc) ||
      targetMissing(row.rut_usuario_idx)
    )
  ) {
    return true;
  }

  if (
    hasValue(row.email) &&
    (
      targetMissing(row.email_enc) ||
      targetMissing(row.email_idx)
    )
  ) {
    return true;
  }

  return false;
}

/* =========================================================
   VALIDACIÓN PREVIA
========================================================= */

/**
 * Valida todos los registros antes de escribir.
 *
 * No imprime:
 * - nombres;
 * - RUT;
 * - emails;
 * - passwords;
 * - ciphertext.
 */
function validateRowsBeforeMigration(
  rows: UsuarioMigrationRow[]
): void {
  for (const row of rows) {
    try {
      if (hasValue(row.nombre_usuario)) {
        normalizeUsername(
          row.nombre_usuario
        );
      }

      if (row.rut_usuario !== null) {
        normalizeRut(
          row.rut_usuario
        );
      }

      if (hasValue(row.email)) {
        const email =
          normalizeEmail(
            row.email
          );

        if (
          !email.includes("@") ||
          email.startsWith("@") ||
          email.endsWith("@")
        ) {
          throw new Error(
            "EMAIL_INVALID"
          );
        }
      }
    } catch {
      throw new Error(
        `Validación fallida en usuario id=${row.id}. ` +
        "Revisa nombre_usuario, RUT o email."
      );
    }
  }
}

/* =========================================================
   CONSTRUCCIÓN DE UPDATE
========================================================= */

/**
 * Genera únicamente columnas pendientes.
 *
 * password NO participa en esta migración.
 *
 * La contraseña debe seguir almacenada mediante hash,
 * nunca mediante cifrado reversible.
 */
function buildMigrationUpdate(
  row: UsuarioMigrationRow
): {
  assignments: string[];
  values: unknown[];
} {
  const assignments: string[] = [];
  const values: unknown[] = [];

  /* -------------------------------------------------------
     NOMBRE USUARIO
  ------------------------------------------------------- */

  if (hasValue(row.nombre_usuario)) {
    if (
      targetMissing(
        row.nombre_usuario_enc
      )
    ) {
      assignments.push(
        "nombre_usuario_enc = ?"
      );

      values.push(
        encryptNullable(
          String(
            row.nombre_usuario
          ).trim()
        )
      );
    }

    if (
      targetMissing(
        row.nombre_usuario_idx
      )
    ) {
      assignments.push(
        "nombre_usuario_idx = ?"
      );

      values.push(
        blindIndex(
          normalizeUsername(
            row.nombre_usuario
          )
        )
      );
    }
  }

  /* -------------------------------------------------------
     RUT USUARIO
  ------------------------------------------------------- */

  if (row.rut_usuario !== null) {
    if (
      targetMissing(
        row.rut_usuario_enc
      )
    ) {
      assignments.push(
        "rut_usuario_enc = ?"
      );

      values.push(
        encryptRut(
          row.rut_usuario
        )
      );
    }

    if (
      targetMissing(
        row.rut_usuario_idx
      )
    ) {
      assignments.push(
        "rut_usuario_idx = ?"
      );

      values.push(
        rutBlindIndex(
          row.rut_usuario
        )
      );
    }
  }

  /* -------------------------------------------------------
     EMAIL
  ------------------------------------------------------- */

  if (hasValue(row.email)) {
    if (
      targetMissing(
        row.email_enc
      )
    ) {
      assignments.push(
        "email_enc = ?"
      );

      values.push(
        encryptNullable(
          normalizeEmail(
            row.email
          )
        )
      );
    }

    if (
      targetMissing(
        row.email_idx
      )
    ) {
      assignments.push(
        "email_idx = ?"
      );

      values.push(
        blindIndex(
          normalizeEmail(
            row.email
          )
        )
      );
    }
  }

  return {
    assignments,
    values,
  };
}

/* =========================================================
   MIGRACIÓN
========================================================= */

async function migrate(): Promise<MigrationStats> {
  await initDb();

  const db = getDb();

  /*
   * Snapshot previo.
   *
   * password deliberadamente NO se selecciona.
   */
  const [rawRows] = await db.query(
    `
      SELECT
        id,

        nombre_usuario,
        nombre_usuario_enc,
        nombre_usuario_idx,

        rut_usuario,
        rut_usuario_enc,
        rut_usuario_idx,

        email,
        email_enc,
        email_idx

      FROM usuarios

      ORDER BY id ASC
    `
  );

  const rows =
    rawRows as UsuarioMigrationRow[];

  /*
   * Validación completa antes del primer UPDATE.
   */
  validateRowsBeforeMigration(
    rows
  );

  const stats: MigrationStats = {
    total: rows.length,
    updated: 0,
    alreadyMigrated: 0,
    withoutSensitiveData: 0,
  };

  /*
   * Toda la migración en una sola transacción.
   *
   * Si falla un usuario:
   *
   * ROLLBACK
   */
  await withTransaction(
    async (conn) => {
      for (const row of rows) {
        if (
          !rowHasSensitiveSource(
            row
          )
        ) {
          stats.withoutSensitiveData += 1;
          continue;
        }

        if (
          !rowNeedsMigration(
            row
          )
        ) {
          stats.alreadyMigrated += 1;
          continue;
        }

        const {
          assignments,
          values,
        } =
          buildMigrationUpdate(
            row
          );

        if (
          assignments.length === 0
        ) {
          stats.alreadyMigrated += 1;
          continue;
        }

        values.push(row.id);

        const sql = `
          UPDATE usuarios
          SET
            ${assignments.join(",\n            ")}
          WHERE id = ?
          LIMIT 1
        `;

        const [result]: any =
          await conn.execute(
            sql,
            values
          );

        if (
          Number(
            result?.affectedRows ??
              0
          ) !== 1
        ) {
          throw new Error(
            `La migración no pudo actualizar correctamente usuario id=${row.id}.`
          );
        }

        stats.updated += 1;
      }
    }
  );

  return stats;
}

/* =========================================================
   VALIDACIÓN POST-MIGRACIÓN
========================================================= */

/**
 * Verifica que todas las fuentes existentes tengan
 * sus equivalentes cifrados/indexados.
 *
 * No expone PII.
 */
async function validateMigrationResult(): Promise<void> {
  const db = getDb();

  const [rows]: any =
    await db.query(
      `
        SELECT
          COUNT(*) AS total,

          SUM(
            nombre_usuario IS NOT NULL
            AND TRIM(nombre_usuario) <> ''
            AND (
              nombre_usuario_enc IS NULL
              OR nombre_usuario_idx IS NULL
            )
          ) AS nombre_pendiente,

          SUM(
            rut_usuario IS NOT NULL
            AND (
              rut_usuario_enc IS NULL
              OR rut_usuario_idx IS NULL
            )
          ) AS rut_pendiente,

          SUM(
            email IS NOT NULL
            AND TRIM(email) <> ''
            AND (
              email_enc IS NULL
              OR email_idx IS NULL
            )
          ) AS email_pendiente

        FROM usuarios
      `
    );

  const result =
    rows?.[0] ?? {};

  const nombrePendiente =
    Number(
      result.nombre_pendiente ??
        0
    );

  const rutPendiente =
    Number(
      result.rut_pendiente ??
        0
    );

  const emailPendiente =
    Number(
      result.email_pendiente ??
        0
    );

  if (
    nombrePendiente > 0 ||
    rutPendiente > 0 ||
    emailPendiente > 0
  ) {
    throw new Error(
      "La validación posterior detectó usuarios con datos sensibles pendientes de migrar."
    );
  }
}

/* =========================================================
   VALIDACIÓN DE DUPLICADOS
========================================================= */

/**
 * Actualmente las columnas plaintext tienen UNIQUE:
 *
 * nombre_usuario
 * rut_usuario
 * email
 *
 * Antes de trasladar la unicidad a los blind indexes,
 * comprobamos que la normalización no genere duplicados.
 */
async function validateBlindIndexDuplicates(): Promise<void> {
  const db = getDb();

  /* -------------------------------------------------------
     NOMBRE USUARIO
  ------------------------------------------------------- */

  const [usernameRows]: any =
    await db.query(
      `
        SELECT
          nombre_usuario_idx,
          COUNT(*) AS cantidad
        FROM usuarios
        WHERE nombre_usuario_idx IS NOT NULL
        GROUP BY nombre_usuario_idx
        HAVING COUNT(*) > 1
      `
    );

  if (
    Array.isArray(usernameRows) &&
    usernameRows.length > 0
  ) {
    throw new Error(
      "Se detectaron nombres de usuario duplicados luego de normalizar nombre_usuario_idx."
    );
  }

  /* -------------------------------------------------------
     RUT
  ------------------------------------------------------- */

  const [rutRows]: any =
    await db.query(
      `
        SELECT
          rut_usuario_idx,
          COUNT(*) AS cantidad
        FROM usuarios
        WHERE rut_usuario_idx IS NOT NULL
        GROUP BY rut_usuario_idx
        HAVING COUNT(*) > 1
      `
    );

  if (
    Array.isArray(rutRows) &&
    rutRows.length > 0
  ) {
    throw new Error(
      "Se detectaron RUT duplicados en rut_usuario_idx."
    );
  }

  /* -------------------------------------------------------
     EMAIL
  ------------------------------------------------------- */

  const [emailRows]: any =
    await db.query(
      `
        SELECT
          email_idx,
          COUNT(*) AS cantidad
        FROM usuarios
        WHERE email_idx IS NOT NULL
        GROUP BY email_idx
        HAVING COUNT(*) > 1
      `
    );

  if (
    Array.isArray(emailRows) &&
    emailRows.length > 0
  ) {
    throw new Error(
      "Se detectaron emails duplicados luego de normalizar email_idx."
    );
  }
}

/* =========================================================
   MAIN
========================================================= */

async function main(): Promise<void> {
  console.log("");
  console.log(
    "============================================"
  );
  console.log(
    " WELI - MIGRACIÓN CIFRADA DE USUARIOS"
  );
  console.log(
    "============================================"
  );
  console.log("");

  /*
   * Validación de claves.
   */
  validateCryptoConfiguration();

  console.log(
    "✅ Configuración criptográfica válida."
  );

  /*
   * Confirma funcionamiento interno del servicio crypto.
   */
  cryptoSelfTest();

  console.log(
    "✅ Self-test criptográfico correcto."
  );

  console.log(
    "🔎 Validando usuarios existentes..."
  );

  const stats =
    await migrate();

  console.log(
    "🔎 Validando resultado de la migración..."
  );

  await validateMigrationResult();

  console.log(
    "✅ Columnas cifradas e índices verificados."
  );

  console.log(
    "🔎 Verificando duplicados en blind indexes..."
  );

  await validateBlindIndexDuplicates();

  console.log(
    "✅ Blind indexes sin duplicados."
  );

  console.log("");
  console.log(
    "============================================"
  );
  console.log(
    " MIGRACIÓN FINALIZADA"
  );
  console.log(
    "============================================"
  );

  console.log(
    `Usuarios revisados:         ${stats.total}`
  );

  console.log(
    `Usuarios migrados:          ${stats.updated}`
  );

  console.log(
    `Ya migrados previamente:    ${stats.alreadyMigrated}`
  );

  console.log(
    `Sin datos para proteger:     ${stats.withoutSensitiveData}`
  );

  console.log("");

  console.log(
    "✅ Las columnas originales NO fueron modificadas."
  );

  console.log(
    "✅ password NO fue leído, modificado ni cifrado."
  );

  console.log(
    "✅ Nombre de usuario, RUT y email quedaron cifrados."
  );

  console.log(
    "✅ Nombre de usuario, RUT y email cuentan con blind indexes."
  );

  console.log(
    "✅ No se imprimieron datos sensibles."
  );

  console.log("");
}

/* =========================================================
   EJECUCIÓN
========================================================= */

main()
  .catch((error) => {
    console.error("");
    console.error(
      "============================================"
    );
    console.error(
      " MIGRACIÓN ABORTADA"
    );
    console.error(
      "============================================"
    );

    if (
      error instanceof Error
    ) {
      console.error(
        error.message
      );
    } else {
      console.error(
        "Se produjo un error desconocido."
      );
    }

    console.error("");

    console.error(
      "❌ Si había una transacción activa, WELI ejecutó ROLLBACK."
    );

    process.exitCode = 1;
  })
  .finally(
    async () => {
      try {
        const db =
          getDb();

        await db.end();
      } catch {
        /*
         * Si la base nunca alcanzó a inicializarse,
         * no hay pool que cerrar.
         */
      }
    }
  );