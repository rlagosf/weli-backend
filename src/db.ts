// src/db.ts
import mysql from "mysql2/promise";
import { CONFIG } from "./config";

let pool: mysql.Pool | null = null;
let initializing: Promise<mysql.Pool> | null = null;

/**
 * Inicializa el pool MySQL una sola vez.
 * Si múltiples módulos llaman initDb() simultáneamente,
 * se reutiliza la misma promesa (no se crean múltiples pools).
 */
export async function initDb(): Promise<mysql.Pool> {
  if (pool) return pool;
  if (initializing) return initializing;

  initializing = (async () => {
    try {
      const newPool = mysql.createPool({
        uri: CONFIG.DATABASE_URL,
        waitForConnections: true,
        connectionLimit: 4,
        queueLimit: 50,

        enableKeepAlive: true,
        keepAliveInitialDelay: 0,
      });

      // Smoke test
      const conn = await newPool.getConnection();
      await conn.ping();

      try {
        const [[{ db: currentDb }]]: any = await conn.query("SELECT DATABASE() AS db");
        console.log(`🟢 Conectado correctamente a la base de datos: ${currentDb}`);
      } catch {
        console.log("⚠️ No se pudo identificar el nombre de la base de datos activa.");
      } finally {
        conn.release();
      }

      pool = newPool;
      console.log("✅ Pool MySQL inicializado correctamente");
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
    throw new Error(
      "La base de datos no está inicializada. Llama a await initDb() antes de usarla."
    );
  }
  return pool;
}

/**
 * ✅ Compatibilidad total: `db.query(...)` con overloads originales.
 * Esto evita el infierno de QueryOptions que te apareció.
 */
export const db: mysql.Pool = new Proxy({} as mysql.Pool, {
  get(_target, prop: keyof mysql.Pool) {
    const real = getDb() as any;
    const value = real[prop];
    return typeof value === "function" ? value.bind(real) : value;
  },
});
