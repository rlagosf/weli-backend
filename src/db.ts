// src/db.ts
import mysql from "mysql2/promise";
import { CONFIG } from "./config";

let pool: mysql.Pool | null = null;
let initializing: Promise<mysql.Pool> | null = null;

/**
 * WELI DB Pool (NinjaHosting / MySQL local)
 *
 * Objetivo: soportar picos (~100 usuarios) SIN abrir 100 conexiones.
 * Un pool sano mantiene conexiones moderadas y encola el resto.
 *
 * Defaults pensados para hosting compartido / VPS liviano:
 * - connectionLimit: 12  (sube/baja según CPU y max_connections del MySQL)
 * - queueLimit: 500      (absorbe ráfagas)
 * - connectTimeout: 10s  (corta conexiones colgadas)
 *
 * Nota: NO usamos acquireTimeout (MySQL2 lo marca inválido).
 */

const DB_POOL_LIMIT = clampInt(process.env.DB_POOL_LIMIT, 12, 2, 50);
const DB_QUEUE_LIMIT = clampInt(process.env.DB_QUEUE_LIMIT, 500, 50, 5000);
const DB_CONNECT_TIMEOUT_MS = clampInt(
  process.env.DB_CONNECT_TIMEOUT_MS,
  10_000,
  1000,
  60_000
);

const DB_ENABLE_MONITOR =
  String(process.env.DB_MONITOR ?? "0") === "1"; // logs pool stats cada cierto rato
const DB_MONITOR_INTERVAL_MS = clampInt(
  process.env.DB_MONITOR_INTERVAL_MS,
  30_000,
  5_000,
  300_000
);

function clampInt(
  v: any,
  fallback: number,
  min: number,
  max: number
): number {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

function safeDbLabel() {
  // evita loggear credenciales del DATABASE_URL
  try {
    const u = new URL(CONFIG.DATABASE_URL);
    return `${u.hostname}:${u.port}${u.pathname || ""}`;
  } catch {
    return "db";
  }
}

async function smokeTest(p: mysql.Pool) {
  const conn = await p.getConnection();
  try {
    await conn.ping();
    try {
      const [[{ db: currentDb }]]: any = await conn.query("SELECT DATABASE() AS db");
      console.log(`🟢 Conectado correctamente a la base de datos: ${currentDb}`);
    } catch {
      console.log("⚠️ No se pudo identificar el nombre de la base de datos activa.");
    }
  } finally {
    conn.release();
  }
}

function startPoolMonitor(p: mysql.Pool) {
  // No todos los builds exponen internals, pero cuando están, ayudan mucho
  if (!DB_ENABLE_MONITOR) return;

  const label = safeDbLabel();
  const timer = setInterval(() => {
    const anyPool: any = p as any;

    // mysql2 internals típicos:
    const all = anyPool?._allConnections?.length;
    const free = anyPool?._freeConnections?.length;
    const queue = anyPool?._connectionQueue?.length;

    // Si no existen, igual no rompemos nada
    console.log("[DB MONITOR]", {
      db: label,
      allConnections: typeof all === "number" ? all : "n/a",
      freeConnections: typeof free === "number" ? free : "n/a",
      queuedRequests: typeof queue === "number" ? queue : "n/a",
      limit: DB_POOL_LIMIT,
      queueLimit: DB_QUEUE_LIMIT,
    });
  }, DB_MONITOR_INTERVAL_MS);

  (timer as any).unref?.();
}

export async function initDb(): Promise<mysql.Pool> {
  if (pool) return pool;
  if (initializing) return initializing;

  initializing = (async () => {
    try {
      const newPool = mysql.createPool({
        uri: CONFIG.DATABASE_URL,

        waitForConnections: true,
        connectionLimit: DB_POOL_LIMIT,
        queueLimit: DB_QUEUE_LIMIT,

        // estabilidad en hostings
        enableKeepAlive: true,
        keepAliveInitialDelay: 0,

        // timeout de conexión (NO de query)
        connectTimeout: DB_CONNECT_TIMEOUT_MS,

        // defaults sanos
        namedPlaceholders: false,
        decimalNumbers: true,
        supportBigNumbers: true,
        bigNumberStrings: false,
      } as mysql.PoolOptions);

      // Eventos (si existen)
      (newPool as any).on?.("error", (err: any) => {
        console.error("❌ MySQL pool error:", err?.code || err?.message || err);
      });

      await smokeTest(newPool);

      pool = newPool;

      console.log(
        `✅ Pool MySQL inicializado correctamente (limit=${DB_POOL_LIMIT}, queue=${DB_QUEUE_LIMIT}, connectTimeoutMs=${DB_CONNECT_TIMEOUT_MS})`
      );

      startPoolMonitor(newPool);

      return newPool;
    } catch (error) {
      console.error("❌ Error al conectar a la base de datos:", error);
      pool = null;
      throw error;
    } finally {
      initializing = null;
    }
  })();

  return initializing;
}

export function getDb(): mysql.Pool {
  if (!pool) {
    throw new Error("DB no inicializada. Llama a await initDb() antes de usarla.");
  }
  return pool;
}

/**
 * Helper seguro para casos donde SÍ necesitas una conexión directa
 * (transacciones, múltiples queries encadenadas).
 * Garantiza release() SIEMPRE.
 */
export async function withConn<T>(fn: (conn: mysql.PoolConnection) => Promise<T>) {
  const p = getDb();
  const conn = await p.getConnection();
  try {
    return await fn(conn);
  } finally {
    conn.release();
  }
}

/**
 * ✅ Compat total: `db.query(...)` y `db.execute(...)` sin pelear con overloads.
 */
export const db: mysql.Pool = new Proxy({} as mysql.Pool, {
  get(_target, prop: keyof mysql.Pool) {
    const real = getDb() as any;
    const value = real[prop];
    return typeof value === "function" ? value.bind(real) : value;
  },
});
