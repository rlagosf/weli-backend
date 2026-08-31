// src/db.ts

import mysql from "mysql2/promise";
import { CONFIG } from "./config";

/* =========================================================
   ESTADO DEL POOL
========================================================= */

let pool: mysql.Pool | null = null;
let initializing: Promise<mysql.Pool> | null = null;

/**
 * WELI DB Pool
 *
 * Objetivo:
 * - reutilizar conexiones;
 * - evitar una conexión MySQL por request;
 * - soportar ráfagas mediante cola;
 * - mantener límites apropiados para hosting/VPS;
 * - centralizar acceso seguro a MySQL.
 *
 * IMPORTANTE:
 * - connectionLimit NO representa usuarios concurrentes.
 * - 100 usuarios no significan 100 conexiones.
 * - las conexiones se reutilizan mediante el pool.
 */

/* =========================================================
   CONFIGURACIÓN
========================================================= */

function clampInt(value: unknown, fallback: number, min: number, max: number): number {
  const parsed = Number(value);

  if (!Number.isFinite(parsed)) {
    return fallback;
  }

  return Math.max(min, Math.min(max, Math.trunc(parsed)));
}

const DB_POOL_LIMIT = clampInt(process.env.DB_POOL_LIMIT, 12, 2, 50);

const DB_QUEUE_LIMIT = clampInt(process.env.DB_QUEUE_LIMIT, 500, 50, 5000);

const DB_CONNECT_TIMEOUT_MS = clampInt(process.env.DB_CONNECT_TIMEOUT_MS, 10_000, 1_000, 60_000);

const DB_ENABLE_MONITOR = String(process.env.DB_MONITOR ?? "0") === "1";

const DB_MONITOR_INTERVAL_MS = clampInt(process.env.DB_MONITOR_INTERVAL_MS, 30_000, 5_000, 300_000);

/* =========================================================
   HELPERS
========================================================= */

/**
 * Devuelve solamente host/puerto/database.
 *
 * Nunca expone:
 * - usuario;
 * - password;
 * - query params sensibles.
 */
function safeDbLabel(): string {
  try {
    const url = new URL(CONFIG.DATABASE_URL);

    return `${url.hostname}:${url.port || "3306"}${url.pathname || ""}`;
  } catch {
    return "db";
  }
}

/* =========================================================
   SMOKE TEST
========================================================= */

async function smokeTest(targetPool: mysql.Pool): Promise<void> {
  const conn = await targetPool.getConnection();

  try {
    await conn.ping();

    try {
      const [rows]: any = await conn.query("SELECT DATABASE() AS db");

      const currentDb = rows?.[0]?.db ?? null;

      if (currentDb) {
        console.log(`🟢 Conectado correctamente a la base de datos: ${currentDb}`);
      } else {
        console.log("⚠️ MySQL conectado, pero no fue posible determinar la base activa.");
      }
    } catch {
      console.log("⚠️ No se pudo identificar el nombre de la base de datos activa.");
    }
  } finally {
    conn.release();
  }
}

/* =========================================================
   MONITOR OPCIONAL
========================================================= */

function startPoolMonitor(targetPool: mysql.Pool): void {
  if (!DB_ENABLE_MONITOR) {
    return;
  }

  const label = safeDbLabel();

  const timer = setInterval(() => {
    /*
     * Son propiedades internas de mysql2.
     * Por eso nunca dependemos funcionalmente de ellas.
     */
    const internalPool: any = targetPool as any;

    const all = internalPool?._allConnections?.length;

    const free = internalPool?._freeConnections?.length;

    const queue = internalPool?._connectionQueue?.length;

    console.log("[DB MONITOR]", {
      db: label,

      allConnections: typeof all === "number" ? all : "n/a",

      freeConnections: typeof free === "number" ? free : "n/a",

      queuedRequests: typeof queue === "number" ? queue : "n/a",

      limit: DB_POOL_LIMIT,

      queueLimit: DB_QUEUE_LIMIT,
    });
  }, DB_MONITOR_INTERVAL_MS);

  /*
   * El monitor no debe mantener vivo
   * el proceso Node por sí solo.
   */
  (timer as any).unref?.();
}

/* =========================================================
   INICIALIZAR DB
========================================================= */

export async function initDb(): Promise<mysql.Pool> {
  /*
   * Ya inicializada.
   */
  if (pool) {
    return pool;
  }

  /*
   * Si dos partes de la aplicación intentan
   * inicializar simultáneamente, ambas esperan
   * la misma Promise.
   */
  if (initializing) {
    return initializing;
  }

  initializing = (async () => {
    let newPool: mysql.Pool | null = null;

    try {
      newPool = mysql.createPool({
        uri: CONFIG.DATABASE_URL,

        /* Pool */
        waitForConnections: true,
        connectionLimit: DB_POOL_LIMIT,
        queueLimit: DB_QUEUE_LIMIT,

        /* Keep alive */
        enableKeepAlive: true,
        keepAliveInitialDelay: 0,

        /*
         * Timeout para establecer conexión.
         * NO representa timeout de consultas.
         */
        connectTimeout: DB_CONNECT_TIMEOUT_MS,

        /*
         * Queries parametrizadas mediante ?.
         */
        namedPlaceholders: false,

        /*
         * DECIMAL(10,2) de nuestra capa financiera
         * puede manejarse como number sin problemas
         * prácticos para los rangos definidos.
         */
        decimalNumbers: true,

        /*
         * Evita conversiones innecesarias de fechas
         * de negocio a Date de JavaScript.
         *
         * Ejemplo:
         * 2026-09-01 permanece "2026-09-01".
         */
        dateStrings: true,

        /*
         * BIGINT.
         *
         * Actualmente dejamos bigNumberStrings=false
         * por compatibilidad con los routers existentes.
         *
         * Si en el futuro pasamos BIGINT a string,
         * habrá que actualizar simultáneamente
         * schemas y normalizadores.
         */
        supportBigNumbers: true,
        bigNumberStrings: false,

        /*
         * No habilitar multipleStatements.
         *
         * El default false es deseable por seguridad.
         */
        multipleStatements: false,
      } as mysql.PoolOptions);

      /*
       * Evento defensivo.
       *
       * No todos los builds/versiones exponen
       * exactamente los mismos eventos.
       */
      (newPool as any).on?.("error", (err: any) => {
        console.error("❌ MySQL pool error:", err?.code || err?.message || err);
      });

      /*
       * La aplicación NO queda disponible
       * hasta confirmar conexión real.
       */
      await smokeTest(newPool);

      /*
       * Solo publicamos el pool después
       * de superar correctamente el smoke test.
       */
      pool = newPool;

      console.log(
        `✅ Pool MySQL inicializado correctamente ` +
          `(limit=${DB_POOL_LIMIT}, ` +
          `queue=${DB_QUEUE_LIMIT}, ` +
          `connectTimeoutMs=${DB_CONNECT_TIMEOUT_MS})`
      );

      startPoolMonitor(newPool);

      return newPool;
    } catch (error) {
      console.error("❌ Error al conectar a la base de datos:", error);

      /*
       * Si createPool() alcanzó a crear recursos
       * antes de fallar el smokeTest, intentamos
       * cerrarlos.
       */
      if (newPool) {
        try {
          await newPool.end();
        } catch (closeError) {
          console.error("❌ Error cerrando pool fallido:", closeError);
        }
      }

      pool = null;

      throw error;
    } finally {
      /*
       * Permite un nuevo intento posterior
       * si la inicialización falla.
       */
      initializing = null;
    }
  })();

  return initializing;
}

/* =========================================================
   OBTENER POOL
========================================================= */

export function getDb(): mysql.Pool {
  if (!pool) {
    throw new Error("DB no inicializada. Llama a await initDb() antes de usarla.");
  }

  return pool;
}

/* =========================================================
   CONEXIÓN DIRECTA SEGURA
========================================================= */

/**
 * Para operaciones que necesitan utilizar
 * una misma conexión:
 *
 * - varias queries relacionadas;
 * - locks;
 * - transacciones;
 * - operaciones secuenciales.
 *
 * release() se ejecuta SIEMPRE.
 */
export async function withConn<T>(fn: (conn: mysql.PoolConnection) => Promise<T>): Promise<T> {
  const targetPool = getDb();

  const conn = await targetPool.getConnection();

  try {
    return await fn(conn);
  } finally {
    conn.release();
  }
}

/* =========================================================
   TRANSACCIONES
========================================================= */

/**
 * Ejecuta una operación MySQL de manera atómica.
 *
 * Flujo:
 *
 * BEGIN
 *   ↓
 * fn(conn)
 *   ↓
 * COMMIT
 *
 * Si ocurre cualquier error:
 *
 * ROLLBACK
 *
 * y la excepción vuelve al router.
 */
export async function withTransaction<T>(fn: (conn: mysql.PoolConnection) => Promise<T>): Promise<T> {
  return withConn(async (conn) => {
    await conn.beginTransaction();

    try {
      const result = await fn(conn);

      await conn.commit();

      return result;
    } catch (error) {
      try {
        await conn.rollback();
      } catch (rollbackError) {
        console.error("❌ Error durante rollback MySQL:", rollbackError);
      }

      throw error;
    }
  });
}

/* =========================================================
   PROXY DE COMPATIBILIDAD
========================================================= */

/**
 * Permite mantener en todos los routers:
 *
 * db.query(...)
 * db.execute(...)
 *
 * sin tener que pasar el pool manualmente.
 *
 * getDb() garantiza que nunca se utilice
 * antes de initDb().
 */
export const db: mysql.Pool = new Proxy({} as mysql.Pool, {
  get(_target, prop: keyof mysql.Pool) {
    const real = getDb() as any;

    const value = real[prop];

    return typeof value === "function" ? value.bind(real) : value;
  },
});
