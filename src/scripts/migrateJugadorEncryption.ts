// src/scripts/migrateJugadorEncryption.ts

import {
  cryptoSelfTest,
  encryptNullable,
  encryptRut,
  normalizeRut,
  rutBlindIndex,
  validateCryptoConfiguration,
} from "../services/crypto";

import { getDb, initDb, withTransaction } from "../db";

/* =========================================================
   TIPOS
========================================================= */

type NullableString = string | null;

type JugadorMigrationRow = {
  id: number;

  nombre_jugador: NullableString;
  nombre_jugador_enc: NullableString;

  rut_jugador: number | string | null;
  rut_jugador_enc: NullableString;
  rut_jugador_idx: NullableString;

  fecha_nacimiento: NullableString;
  fecha_nacimiento_enc: NullableString;

  telefono: NullableString;
  telefono_enc: NullableString;

  email: NullableString;
  email_enc: NullableString;

  direccion: NullableString;
  direccion_enc: NullableString;

  nombre_apoderado: NullableString;
  nombre_apoderado_enc: NullableString;

  rut_apoderado: number | string | null;
  rut_apoderado_enc: NullableString;
  rut_apoderado_idx: NullableString;

  telefono_apoderado: NullableString;
  telefono_apoderado_enc: NullableString;

  observaciones: NullableString;
  observaciones_enc: NullableString;
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

/**
 * Solamente para decidir si una fila tiene algo que migrar.
 * No imprime ni devuelve PII.
 */
function rowHasSensitiveSource(row: JugadorMigrationRow): boolean {
  return (
    hasValue(row.nombre_jugador) ||
    row.rut_jugador !== null ||
    hasValue(row.fecha_nacimiento) ||
    hasValue(row.telefono) ||
    hasValue(row.email) ||
    hasValue(row.direccion) ||
    hasValue(row.nombre_apoderado) ||
    row.rut_apoderado !== null ||
    hasValue(row.telefono_apoderado) ||
    hasValue(row.observaciones)
  );
}

/**
 * Determina si existe al menos un campo pendiente de migración.
 */
function rowNeedsMigration(row: JugadorMigrationRow): boolean {
  if (hasValue(row.nombre_jugador) && targetMissing(row.nombre_jugador_enc)) {
    return true;
  }

  if (row.rut_jugador !== null && (targetMissing(row.rut_jugador_enc) || targetMissing(row.rut_jugador_idx))) {
    return true;
  }

  if (hasValue(row.fecha_nacimiento) && targetMissing(row.fecha_nacimiento_enc)) {
    return true;
  }

  if (hasValue(row.telefono) && targetMissing(row.telefono_enc)) {
    return true;
  }

  if (hasValue(row.email) && targetMissing(row.email_enc)) {
    return true;
  }

  if (hasValue(row.direccion) && targetMissing(row.direccion_enc)) {
    return true;
  }

  if (hasValue(row.nombre_apoderado) && targetMissing(row.nombre_apoderado_enc)) {
    return true;
  }

  if (row.rut_apoderado !== null && (targetMissing(row.rut_apoderado_enc) || targetMissing(row.rut_apoderado_idx))) {
    return true;
  }

  if (hasValue(row.telefono_apoderado) && targetMissing(row.telefono_apoderado_enc)) {
    return true;
  }

  if (hasValue(row.observaciones) && targetMissing(row.observaciones_enc)) {
    return true;
  }

  return false;
}

/* =========================================================
   VALIDACIÓN PREVIA
========================================================= */

/**
 * Antes de escribir una sola fila:
 *
 * - valida todos los RUT existentes;
 * - verifica que cumplan la regla WELI;
 * - no imprime el RUT ni otro dato personal.
 *
 * Si existe una anomalía, aborta TODA la migración.
 */
function validateRowsBeforeMigration(rows: JugadorMigrationRow[]): void {
  for (const row of rows) {
    try {
      if (row.rut_jugador !== null) {
        normalizeRut(row.rut_jugador);
      }

      if (row.rut_apoderado !== null) {
        normalizeRut(row.rut_apoderado);
      }
    } catch {
      throw new Error(
        `Validación fallida en jugador id=${row.id}. ` + "Existe un RUT que no cumple la regla de 7 u 8 dígitos sin DV."
      );
    }
  }
}

/* =========================================================
   CONSTRUCCIÓN DE UPDATE
========================================================= */

/**
 * Genera únicamente las columnas todavía pendientes.
 *
 * Los nombres de columnas están definidos internamente.
 * Ningún nombre de columna proviene de input externo.
 *
 * Los valores siempre se envían mediante placeholders (?).
 */
function buildMigrationUpdate(row: JugadorMigrationRow): {
  assignments: string[];
  values: unknown[];
} {
  const assignments: string[] = [];
  const values: unknown[] = [];

  /* -------------------------------------------------------
     JUGADOR
  ------------------------------------------------------- */

  if (hasValue(row.nombre_jugador) && targetMissing(row.nombre_jugador_enc)) {
    assignments.push("nombre_jugador_enc = ?");
    values.push(encryptNullable(row.nombre_jugador));
  }

  if (row.rut_jugador !== null) {
    /*
     * Enc e índice se manejan separadamente para soportar
     * una eventual migración previa incompleta.
     */

    if (targetMissing(row.rut_jugador_enc)) {
      assignments.push("rut_jugador_enc = ?");
      values.push(encryptRut(row.rut_jugador));
    }

    if (targetMissing(row.rut_jugador_idx)) {
      assignments.push("rut_jugador_idx = ?");
      values.push(rutBlindIndex(row.rut_jugador));
    }
  }

  if (hasValue(row.fecha_nacimiento) && targetMissing(row.fecha_nacimiento_enc)) {
    assignments.push("fecha_nacimiento_enc = ?");
    values.push(encryptNullable(row.fecha_nacimiento));
  }

  if (hasValue(row.telefono) && targetMissing(row.telefono_enc)) {
    assignments.push("telefono_enc = ?");
    values.push(encryptNullable(row.telefono));
  }

  if (hasValue(row.email) && targetMissing(row.email_enc)) {
    assignments.push("email_enc = ?");
    values.push(encryptNullable(row.email));
  }

  if (hasValue(row.direccion) && targetMissing(row.direccion_enc)) {
    assignments.push("direccion_enc = ?");
    values.push(encryptNullable(row.direccion));
  }

  /* -------------------------------------------------------
     APODERADO
  ------------------------------------------------------- */

  if (hasValue(row.nombre_apoderado) && targetMissing(row.nombre_apoderado_enc)) {
    assignments.push("nombre_apoderado_enc = ?");
    values.push(encryptNullable(row.nombre_apoderado));
  }

  if (row.rut_apoderado !== null) {
    if (targetMissing(row.rut_apoderado_enc)) {
      assignments.push("rut_apoderado_enc = ?");
      values.push(encryptRut(row.rut_apoderado));
    }

    if (targetMissing(row.rut_apoderado_idx)) {
      assignments.push("rut_apoderado_idx = ?");
      values.push(rutBlindIndex(row.rut_apoderado));
    }
  }

  if (hasValue(row.telefono_apoderado) && targetMissing(row.telefono_apoderado_enc)) {
    assignments.push("telefono_apoderado_enc = ?");
    values.push(encryptNullable(row.telefono_apoderado));
  }

  if (hasValue(row.observaciones) && targetMissing(row.observaciones_enc)) {
    assignments.push("observaciones_enc = ?");
    values.push(encryptNullable(row.observaciones));
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
  /*
   * Inicializa el pool usando exactamente la configuración
   * oficial de WELI.
   */
  await initDb();

  /*
   * Obtenemos snapshot actual solamente para validar.
   *
   * No se escribe nada todavía.
   */
  const db = getDb();

  const [rawRows] = await db.query(
    `
      SELECT
        id,

        nombre_jugador,
        nombre_jugador_enc,

        rut_jugador,
        rut_jugador_enc,
        rut_jugador_idx,

        fecha_nacimiento,
        fecha_nacimiento_enc,

        telefono,
        telefono_enc,

        email,
        email_enc,

        direccion,
        direccion_enc,

        nombre_apoderado,
        nombre_apoderado_enc,

        rut_apoderado,
        rut_apoderado_enc,
        rut_apoderado_idx,

        telefono_apoderado,
        telefono_apoderado_enc,

        observaciones,
        observaciones_enc

      FROM jugadores

      ORDER BY id ASC
    `
  );

  const rows = rawRows as JugadorMigrationRow[];

  /*
   * VALIDACIÓN COMPLETA ANTES DEL PRIMER UPDATE.
   */
  validateRowsBeforeMigration(rows);

  const stats: MigrationStats = {
    total: rows.length,
    updated: 0,
    alreadyMigrated: 0,
    withoutSensitiveData: 0,
  };

  /*
   * La escritura completa se realiza dentro de una sola
   * transacción.
   *
   * Si una fila falla:
   *
   * ROLLBACK
   *
   * y ninguna modificación de esta ejecución permanece.
   */
  await withTransaction(async (conn) => {
    for (const row of rows) {
      if (!rowHasSensitiveSource(row)) {
        stats.withoutSensitiveData += 1;
        continue;
      }

      if (!rowNeedsMigration(row)) {
        stats.alreadyMigrated += 1;
        continue;
      }

      const { assignments, values } = buildMigrationUpdate(row);

      if (!assignments.length) {
        stats.alreadyMigrated += 1;
        continue;
      }

      /*
       * El ID proviene de la consulta SELECT interna.
       * Aun así se envía como parámetro.
       */
      values.push(row.id);

      const sql = `
        UPDATE jugadores
        SET
          ${assignments.join(",\n          ")}
        WHERE id = ?
        LIMIT 1
      `;

      const [result]: any = await conn.execute(sql, values);

      if (Number(result?.affectedRows ?? 0) !== 1) {
        throw new Error(`La migración no pudo actualizar correctamente jugador id=${row.id}.`);
      }

      stats.updated += 1;
    }
  });

  return stats;
}

/* =========================================================
   MAIN
========================================================= */

async function main(): Promise<void> {
  console.log("");
  console.log("============================================");
  console.log(" WELI - MIGRACIÓN DE DATOS CIFRADOS");
  console.log("============================================");
  console.log("");

  /*
   * Las claves se validan antes de acceder a los datos.
   */
  validateCryptoConfiguration();

  console.log("✅ Configuración criptográfica válida.");

  /*
   * Confirmamos que cifrado/descifrado e índices funcionan
   * antes de comenzar.
   */
  cryptoSelfTest();

  console.log("✅ Self-test criptográfico correcto.");

  console.log("🔎 Validando registros existentes...");

  const stats = await migrate();

  console.log("");
  console.log("============================================");
  console.log(" MIGRACIÓN FINALIZADA");
  console.log("============================================");

  console.log(`Registros revisados:        ${stats.total}`);

  console.log(`Registros migrados:         ${stats.updated}`);

  console.log(`Ya migrados previamente:    ${stats.alreadyMigrated}`);

  console.log(`Sin datos para proteger:     ${stats.withoutSensitiveData}`);

  console.log("");
  console.log("✅ No se modificaron ni eliminaron las columnas originales.");

  console.log("✅ No se imprimieron datos personales ni claves.");

  console.log("✅ Los datos cifrados quedaron en las columnas paralelas.");

  console.log("");
}

/* =========================================================
   EJECUCIÓN
========================================================= */

main()
  .catch((error) => {
    console.error("");
    console.error("============================================");
    console.error(" MIGRACIÓN ABORTADA");
    console.error("============================================");

    /*
     * No imprimimos objetos completos porque eventualmente
     * podrían incorporar parámetros o información sensible.
     */
    if (error instanceof Error) {
      console.error(error.message);
    } else {
      console.error("Se produjo un error desconocido.");
    }

    console.error("");
    console.error("❌ Si comenzó una transacción, WELI ejecutó ROLLBACK.");

    process.exitCode = 1;
  })
  .finally(async () => {
    /*
     * El script es un proceso independiente.
     * Cerramos el pool cuando termina.
     */
    try {
      const db = getDb();

      await db.end();
    } catch {
      /*
       * Si la DB nunca alcanzó a inicializarse,
       * no existe pool que cerrar.
       */
    }
  });
