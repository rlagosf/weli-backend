// src/scripts/migrateApoderadosAuthEncryption.ts

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

type ApoderadoAuthMigrationRow = {
  apoderado_id: number | string;

  rut_apoderado: string;
  rut_apoderado_enc: NullableString;
  rut_apoderado_idx: NullableString;

  nombre_apoderado: NullableString;
  nombre_apoderado_enc: NullableString;
  nombre_apoderado_idx: NullableString;
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
   NORMALIZACIÓN
========================================================= */

/**
 * Nombre canónico del apoderado para blind index.
 *
 * Se usa solamente para búsqueda exacta / consistencia.
 *
 * - trim
 * - lowercase
 * - espacios internos normalizados
 */
function normalizeApoderadoName(value: unknown): string {
  const normalized = String(value ?? "")
    .trim()
    .replace(/\s+/g, " ")
    .toLowerCase();

  if (!normalized) {
    throw new Error(
      "El nombre del apoderado no puede estar vacío."
    );
  }

  return normalized;
}

/* =========================================================
   DETECCIÓN DE DATOS
========================================================= */

function rowHasSensitiveSource(
  row: ApoderadoAuthMigrationRow
): boolean {
  return (
    hasValue(row.rut_apoderado) ||
    hasValue(row.nombre_apoderado)
  );
}

function rowNeedsMigration(
  row: ApoderadoAuthMigrationRow
): boolean {
  if (
    hasValue(row.rut_apoderado) &&
    (
      targetMissing(row.rut_apoderado_enc) ||
      targetMissing(row.rut_apoderado_idx)
    )
  ) {
    return true;
  }

  if (
    hasValue(row.nombre_apoderado) &&
    (
      targetMissing(row.nombre_apoderado_enc) ||
      targetMissing(row.nombre_apoderado_idx)
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
 * password_hash NO se selecciona ni se toca.
 */
function validateRowsBeforeMigration(
  rows: ApoderadoAuthMigrationRow[]
): void {
  for (const row of rows) {
    try {
      if (hasValue(row.rut_apoderado)) {
        normalizeRut(
          row.rut_apoderado
        );
      }

      if (hasValue(row.nombre_apoderado)) {
        normalizeApoderadoName(
          row.nombre_apoderado
        );
      }
    } catch {
      throw new Error(
        `Validación fallida en apoderado_id=${row.apoderado_id}. ` +
        "Revisa rut_apoderado o nombre_apoderado."
      );
    }
  }
}

/* =========================================================
   CONSTRUCCIÓN DE UPDATE
========================================================= */

function buildMigrationUpdate(
  row: ApoderadoAuthMigrationRow
): {
  assignments: string[];
  values: unknown[];
} {
  const assignments: string[] = [];
  const values: unknown[] = [];

  /* -------------------------------------------------------
     RUT
  ------------------------------------------------------- */

  if (hasValue(row.rut_apoderado)) {
    if (
      targetMissing(
        row.rut_apoderado_enc
      )
    ) {
      assignments.push(
        "rut_apoderado_enc = ?"
      );

      values.push(
        encryptRut(
          row.rut_apoderado
        )
      );
    }

    if (
      targetMissing(
        row.rut_apoderado_idx
      )
    ) {
      assignments.push(
        "rut_apoderado_idx = ?"
      );

      values.push(
        rutBlindIndex(
          row.rut_apoderado
        )
      );
    }
  }

  /* -------------------------------------------------------
     NOMBRE
  ------------------------------------------------------- */

  if (hasValue(row.nombre_apoderado)) {
    if (
      targetMissing(
        row.nombre_apoderado_enc
      )
    ) {
      assignments.push(
        "nombre_apoderado_enc = ?"
      );

      values.push(
        encryptNullable(
          String(
            row.nombre_apoderado
          ).trim()
        )
      );
    }

    if (
      targetMissing(
        row.nombre_apoderado_idx
      )
    ) {
      assignments.push(
        "nombre_apoderado_idx = ?"
      );

      values.push(
        blindIndex(
          normalizeApoderadoName(
            row.nombre_apoderado
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
   * password_hash se omite deliberadamente.
   */
  const [rawRows] = await db.query(
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

      ORDER BY apoderado_id ASC
    `
  );

  const rows =
    rawRows as ApoderadoAuthMigrationRow[];

  validateRowsBeforeMigration(
    rows
  );

  const stats: MigrationStats = {
    total: rows.length,
    updated: 0,
    alreadyMigrated: 0,
    withoutSensitiveData: 0,
  };

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

        values.push(
          row.apoderado_id
        );

        const sql = `
          UPDATE apoderados_auth
          SET
            ${assignments.join(",\n            ")}
          WHERE apoderado_id = ?
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
            `La migración no pudo actualizar correctamente apoderado_id=${row.apoderado_id}.`
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

async function validateMigrationResult(): Promise<void> {
  const db = getDb();

  const [rows]: any =
    await db.query(
      `
        SELECT
          COUNT(*) AS total,

          SUM(
            rut_apoderado IS NOT NULL
            AND TRIM(rut_apoderado) <> ''
            AND (
              rut_apoderado_enc IS NULL
              OR rut_apoderado_idx IS NULL
            )
          ) AS rut_pendiente,

          SUM(
            nombre_apoderado IS NOT NULL
            AND TRIM(nombre_apoderado) <> ''
            AND (
              nombre_apoderado_enc IS NULL
              OR nombre_apoderado_idx IS NULL
            )
          ) AS nombre_pendiente

        FROM apoderados_auth
      `
    );

  const result =
    rows?.[0] ?? {};

  const rutPendiente =
    Number(
      result.rut_pendiente ??
        0
    );

  const nombrePendiente =
    Number(
      result.nombre_pendiente ??
        0
    );

  if (
    rutPendiente > 0 ||
    nombrePendiente > 0
  ) {
    throw new Error(
      "La validación posterior detectó apoderados con datos sensibles pendientes de migrar."
    );
  }
}

/* =========================================================
   VALIDACIÓN DE DUPLICADOS
========================================================= */

async function validateBlindIndexDuplicates(): Promise<void> {
  const db = getDb();

  /* -------------------------------------------------------
     RUT
  ------------------------------------------------------- */

  const [rutRows]: any =
    await db.query(
      `
        SELECT
          rut_apoderado_idx,
          COUNT(*) AS cantidad
        FROM apoderados_auth
        WHERE rut_apoderado_idx IS NOT NULL
        GROUP BY rut_apoderado_idx
        HAVING COUNT(*) > 1
      `
    );

  if (
    Array.isArray(rutRows) &&
    rutRows.length > 0
  ) {
    throw new Error(
      "Se detectaron RUT de apoderados duplicados en rut_apoderado_idx."
    );
  }

  /* -------------------------------------------------------
     NOMBRE
  ------------------------------------------------------- */

  const [nombreRows]: any =
    await db.query(
      `
        SELECT
          nombre_apoderado_idx,
          COUNT(*) AS cantidad
        FROM apoderados_auth
        WHERE nombre_apoderado_idx IS NOT NULL
        GROUP BY nombre_apoderado_idx
        HAVING COUNT(*) > 1
      `
    );

  /*
   * OJO:
   *
   * nombres repetidos NO son necesariamente un error real,
   * porque dos personas distintas pueden llamarse igual.
   *
   * Por eso aquí NO abortamos la migración.
   *
   * Solamente confirmamos que el índice fue generado.
   */
  void nombreRows;
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
    " WELI - MIGRACIÓN CIFRADA APODERADOS_AUTH"
  );
  console.log(
    "============================================"
  );
  console.log("");

  validateCryptoConfiguration();

  console.log(
    "✅ Configuración criptográfica válida."
  );

  cryptoSelfTest();

  console.log(
    "✅ Self-test criptográfico correcto."
  );

  console.log(
    "🔎 Validando apoderados existentes..."
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
    "🔎 Verificando blind index de RUT..."
  );

  await validateBlindIndexDuplicates();

  console.log(
    "✅ Blind index de RUT sin duplicados."
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
    `Apoderados revisados:       ${stats.total}`
  );

  console.log(
    `Apoderados migrados:        ${stats.updated}`
  );

  console.log(
    `Ya migrados previamente:    ${stats.alreadyMigrated}`
  );

  console.log(
    `Sin datos para proteger:     ${stats.withoutSensitiveData}`
  );

  console.log("");

  console.log(
    "✅ rut_apoderado quedó cifrado e indexado."
  );

  console.log(
    "✅ nombre_apoderado quedó cifrado e indexado."
  );

  console.log(
    "✅ password_hash NO fue leído, modificado ni cifrado."
  );

  console.log(
    "✅ must_change_password, estado_id y fechas permanecieron intactos."
  );

  console.log(
    "✅ Las columnas originales siguen disponibles durante la fase dual."
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
         * Si initDb nunca terminó,
         * no existe pool que cerrar.
         */
      }
    }
  );