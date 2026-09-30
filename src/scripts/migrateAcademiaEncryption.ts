// src/scripts/migrateAcademiaEncryption.ts

import {
  blindIndex,
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

type AcademiaMigrationRow = {
  id: number;

  nombre: NullableString;
  nombre_enc: NullableString;
  nombre_idx: NullableString;

  rut_academia: number | string | null;
  rut_academia_enc: NullableString;
  rut_academia_idx: NullableString;

  direccion: NullableString;
  direccion_enc: NullableString;

  email: NullableString;
  email_enc: NullableString;
};

type MigrationStats = {
  total: number;
  updated: number;
  alreadyMigrated: number;
  withoutSensitiveData: number;
};

/* =========================================================
   HELPERS GENERALES
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
   NORMALIZACIÓN DEL NOMBRE DE ACADEMIA
========================================================= */

/**
 * El nombre visible se cifra tal como está almacenado.
 *
 * Para nombre_idx usamos una representación canónica:
 *
 * - trim
 * - minúsculas
 * - espacios internos normalizados
 *
 * Ejemplo:
 *
 * "  Academia   Los Leones "
 *
 * ↓
 *
 * "academia los leones"
 *
 * De este modo podemos hacer búsquedas exactas / unicidad
 * mediante HMAC sin revelar el nombre en MySQL.
 */
function normalizeAcademiaName(value: unknown): string {
  const normalized = String(value ?? "")
    .trim()
    .replace(/\s+/g, " ")
    .toLowerCase();

  if (!normalized) {
    throw new Error("El nombre de academia no puede estar vacío.");
  }

  return normalized;
}

/* =========================================================
   NORMALIZACIÓN DE EMAIL
========================================================= */

/**
 * El email se normaliza de manera consistente antes
 * de cifrarlo.
 *
 * En esta fase todavía NO generamos email_idx.
 */
function normalizeEmail(value: unknown): string {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

/* =========================================================
   DETECCIÓN DE DATOS
========================================================= */

function rowHasSensitiveSource(row: AcademiaMigrationRow): boolean {
  return hasValue(row.nombre) || row.rut_academia !== null || hasValue(row.direccion) || hasValue(row.email);
}

function rowNeedsMigration(row: AcademiaMigrationRow): boolean {
  if (hasValue(row.nombre) && (targetMissing(row.nombre_enc) || targetMissing(row.nombre_idx))) {
    return true;
  }

  if (row.rut_academia !== null && (targetMissing(row.rut_academia_enc) || targetMissing(row.rut_academia_idx))) {
    return true;
  }

  if (hasValue(row.direccion) && targetMissing(row.direccion_enc)) {
    return true;
  }

  if (hasValue(row.email) && targetMissing(row.email_enc)) {
    return true;
  }

  return false;
}

/* =========================================================
   VALIDACIÓN PREVIA
========================================================= */

/**
 * Antes de escribir:
 *
 * - comprueba nombres;
 * - comprueba RUT;
 * - comprueba formato básico de email si existe;
 * - no imprime PII.
 *
 * Una anomalía aborta la migración completa.
 */
function validateRowsBeforeMigration(rows: AcademiaMigrationRow[]): void {
  for (const row of rows) {
    try {
      if (hasValue(row.nombre)) {
        normalizeAcademiaName(row.nombre);
      }

      if (row.rut_academia !== null) {
        normalizeRut(row.rut_academia);
      }

      if (hasValue(row.email)) {
        const email = normalizeEmail(row.email);

        /*
         * Validación deliberadamente básica.
         *
         * No queremos rechazar direcciones válidas mediante
         * una expresión regular excesivamente restrictiva.
         */
        if (!email.includes("@") || email.startsWith("@") || email.endsWith("@")) {
          throw new Error("EMAIL_INVALID");
        }
      }
    } catch {
      throw new Error(
        `Validación fallida en academia id=${row.id}. ` + "Revisa nombre, RUT o email antes de continuar."
      );
    }
  }
}

/* =========================================================
   CONSTRUCCIÓN DE UPDATE
========================================================= */

/**
 * Solamente añade columnas que todavía estén pendientes.
 *
 * Ningún nombre de columna viene desde input externo.
 * Todos los valores viajan mediante placeholders (?).
 */
function buildMigrationUpdate(row: AcademiaMigrationRow): {
  assignments: string[];
  values: unknown[];
} {
  const assignments: string[] = [];
  const values: unknown[] = [];

  /* -------------------------------------------------------
     NOMBRE
  ------------------------------------------------------- */

  if (hasValue(row.nombre)) {
    if (targetMissing(row.nombre_enc)) {
      assignments.push("nombre_enc = ?");

      values.push(encryptNullable(String(row.nombre).trim()));
    }

    if (targetMissing(row.nombre_idx)) {
      assignments.push("nombre_idx = ?");

      values.push(blindIndex(normalizeAcademiaName(row.nombre)));
    }
  }

  /* -------------------------------------------------------
     RUT ACADEMIA
  ------------------------------------------------------- */

  if (row.rut_academia !== null) {
    if (targetMissing(row.rut_academia_enc)) {
      assignments.push("rut_academia_enc = ?");

      values.push(encryptRut(row.rut_academia));
    }

    if (targetMissing(row.rut_academia_idx)) {
      assignments.push("rut_academia_idx = ?");

      values.push(rutBlindIndex(row.rut_academia));
    }
  }

  /* -------------------------------------------------------
     DIRECCIÓN
  ------------------------------------------------------- */

  if (hasValue(row.direccion) && targetMissing(row.direccion_enc)) {
    assignments.push("direccion_enc = ?");

    values.push(encryptNullable(String(row.direccion).trim()));
  }

  /* -------------------------------------------------------
     EMAIL
  ------------------------------------------------------- */

  if (hasValue(row.email) && targetMissing(row.email_enc)) {
    assignments.push("email_enc = ?");

    values.push(encryptNullable(normalizeEmail(row.email)));
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
   * Usa exactamente el pool oficial de WELI.
   */
  await initDb();

  const db = getDb();

  /*
   * Snapshot previo.
   *
   * Todavía no escribimos nada.
   */
  const [rawRows] = await db.query(
    `
      SELECT
        id,

        nombre,
        nombre_enc,
        nombre_idx,

        rut_academia,
        rut_academia_enc,
        rut_academia_idx,

        direccion,
        direccion_enc,

        email,
        email_enc

      FROM academias

      ORDER BY id ASC
    `
  );

  const rows = rawRows as AcademiaMigrationRow[];

  /*
   * Validación COMPLETA antes del primer UPDATE.
   */
  validateRowsBeforeMigration(rows);

  const stats: MigrationStats = {
    total: rows.length,
    updated: 0,
    alreadyMigrated: 0,
    withoutSensitiveData: 0,
  };

  /*
   * Toda la migración queda dentro de una transacción.
   *
   * Si una academia falla:
   *
   * ROLLBACK
   *
   * y esta ejecución no deja una migración parcial.
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

      if (assignments.length === 0) {
        stats.alreadyMigrated += 1;
        continue;
      }

      values.push(row.id);

      const sql = `
          UPDATE academias
          SET
            ${assignments.join(",\n            ")}
          WHERE id = ?
          LIMIT 1
        `;

      const [result]: any = await conn.execute(sql, values);

      if (Number(result?.affectedRows ?? 0) !== 1) {
        throw new Error(`La migración no pudo actualizar correctamente academia id=${row.id}.`);
      }

      stats.updated += 1;
    }
  });

  return stats;
}

/* =========================================================
   VALIDACIÓN POST-MIGRACIÓN
========================================================= */

/**
 * Comprueba únicamente presencia / consistencia estructural.
 *
 * No imprime:
 *
 * - nombres;
 * - RUT;
 * - emails;
 * - direcciones;
 * - ciphertext.
 */
async function validateMigrationResult(): Promise<void> {
  const db = getDb();

  const [rows]: any = await db.query(
    `
        SELECT
          COUNT(*) AS total,

          SUM(
            nombre IS NOT NULL
            AND TRIM(nombre) <> ''
            AND (
              nombre_enc IS NULL
              OR nombre_idx IS NULL
            )
          ) AS nombre_pendiente,

          SUM(
            rut_academia IS NOT NULL
            AND (
              rut_academia_enc IS NULL
              OR rut_academia_idx IS NULL
            )
          ) AS rut_pendiente,

          SUM(
            direccion IS NOT NULL
            AND TRIM(direccion) <> ''
            AND direccion_enc IS NULL
          ) AS direccion_pendiente,

          SUM(
            email IS NOT NULL
            AND TRIM(email) <> ''
            AND email_enc IS NULL
          ) AS email_pendiente

        FROM academias
      `
  );

  const result = rows?.[0] ?? {};

  const nombrePendiente = Number(result.nombre_pendiente ?? 0);

  const rutPendiente = Number(result.rut_pendiente ?? 0);

  const direccionPendiente = Number(result.direccion_pendiente ?? 0);

  const emailPendiente = Number(result.email_pendiente ?? 0);

  if (nombrePendiente > 0 || rutPendiente > 0 || direccionPendiente > 0 || emailPendiente > 0) {
    throw new Error("La validación posterior detectó campos sensibles pendientes de migrar.");
  }
}

/* =========================================================
   VALIDACIÓN DE DUPLICADOS DEL BLIND INDEX
========================================================= */

/**
 * El nombre original posee UNIQUE(nombre).
 *
 * Antes de convertir nombre_idx en UNIQUE en una etapa
 * posterior, verificamos que no existan colisiones lógicas.
 */
async function validateNameIndexes(): Promise<void> {
  const db = getDb();

  const [rows]: any = await db.query(
    `
        SELECT
          nombre_idx,
          COUNT(*) AS cantidad
        FROM academias
        WHERE nombre_idx IS NOT NULL
        GROUP BY nombre_idx
        HAVING COUNT(*) > 1
      `
  );

  if (Array.isArray(rows) && rows.length > 0) {
    throw new Error("Se detectaron nombres de academia duplicados al normalizar nombre_idx.");
  }
}

/* =========================================================
   MAIN
========================================================= */

async function main(): Promise<void> {
  console.log("");
  console.log("============================================");
  console.log(" WELI - MIGRACIÓN CIFRADA DE ACADEMIAS");
  console.log("============================================");
  console.log("");

  /*
   * Claves correctas antes de acceder a datos.
   */
  validateCryptoConfiguration();

  console.log("✅ Configuración criptográfica válida.");

  /*
   * Cifrado, descifrado y blind indexes operativos.
   */
  cryptoSelfTest();

  console.log("✅ Self-test criptográfico correcto.");

  console.log("🔎 Validando academias existentes...");

  const stats = await migrate();

  console.log("🔎 Validando resultado de la migración...");

  await validateMigrationResult();

  console.log("✅ Columnas cifradas verificadas.");

  console.log("🔎 Verificando blind indexes de nombres...");

  await validateNameIndexes();

  console.log("✅ Blind indexes sin duplicados.");

  console.log("");
  console.log("============================================");
  console.log(" MIGRACIÓN FINALIZADA");
  console.log("============================================");

  console.log(`Academias revisadas:        ${stats.total}`);

  console.log(`Academias migradas:         ${stats.updated}`);

  console.log(`Ya migradas previamente:    ${stats.alreadyMigrated}`);

  console.log(`Sin datos para proteger:     ${stats.withoutSensitiveData}`);

  console.log("");

  console.log("✅ Las columnas originales NO fueron modificadas.");

  console.log("✅ No se imprimieron datos personales ni comerciales.");

  console.log("✅ Nombre, RUT, dirección y email quedaron reflejados en sus columnas cifradas.");

  console.log("✅ Nombre y RUT cuentan con blind indexes.");

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
     * No imprimimos el objeto completo del error:
     * podría contener parámetros SQL o información sensible.
     */
    if (error instanceof Error) {
      console.error(error.message);
    } else {
      console.error("Se produjo un error desconocido.");
    }

    console.error("");

    console.error("❌ Si había una transacción activa, WELI ejecutó ROLLBACK.");

    process.exitCode = 1;
  })
  .finally(async () => {
    /*
     * Proceso independiente:
     * cerramos el pool antes de terminar.
     */
    try {
      const db = getDb();

      await db.end();
    } catch {
      /*
       * Si initDb nunca terminó,
       * no hay pool que cerrar.
       */
    }
  });
