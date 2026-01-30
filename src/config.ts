// src/config.ts
import fs from "fs";
import path from "path";
import dotenv from "dotenv";

/* ──────────────────────────────────────────────────────────────
   Carga de variables según entorno
────────────────────────────────────────────────────────────── */
const isProd = process.env.NODE_ENV === "production";
const envFile = isProd ? ".env.production" : ".env.development";
const envPath = path.resolve(process.cwd(), envFile);

if (fs.existsSync(envPath)) {
  dotenv.config({ path: envPath });
  console.log(`🟢 Cargando variables desde ${envFile}`);
} else {
  console.warn(`⚠️ No se encontró ${envFile}, usando variables del entorno`);
}

/* ──────────────────────────────────────────────────────────────
   Helpers
────────────────────────────────────────────────────────────── */
const must = (key: string, fallback?: string) => {
  const raw = process.env[key] ?? fallback;
  if (raw === undefined || String(raw).trim() === "") {
    throw new Error(`Falta variable de entorno: ${key}`);
  }
  return String(raw).trim();
};

// no obligatoria, pero sanitiza whitespace
const opt = (key: string, fallback: string) =>
  String(process.env[key] ?? fallback).trim();

const optBool01 = (key: string, fallback: "0" | "1" = "0") => {
  const v = opt(key, fallback);
  return v === "1" ? "1" : "0";
};

// normaliza origins tipo "a,b,c" -> ["a","b","c"] (sin romper compat)
const optCsv = (key: string, fallback: string) =>
  opt(key, fallback)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

/* ──────────────────────────────────────────────────────────────
   CONFIG Global (WELI)
────────────────────────────────────────────────────────────── */
export const CONFIG = {
  NODE_ENV: process.env.NODE_ENV ?? "development",

  PORT: Number.isFinite(Number(process.env.PORT))
    ? Number(process.env.PORT)
    : 8000,

  JWT_SECRET: isProd
    ? must("JWT_SECRET")
    : must("JWT_SECRET", "wR4%7nHq$2@z!8Fp^fC_39mLx$KjRqPzD"),

  JWT_EXPIRES_IN: opt("JWT_EXPIRES_IN", "12h"),

  // ✅ Identidad JWT (alineado con el rename oficial a WELI)
  // Esto impacta auth.ts / auth_apoderado.ts y el verify en index.ts si lo ajustas.
  JWT_ISSUER: opt("JWT_ISSUER", "weli"),
  JWT_AUDIENCE: opt("JWT_AUDIENCE", "web"),

  // ✅ Toggle de logs de performance en auth (0/1)
  AUTH_PERF_LOG: optBool01("AUTH_PERF_LOG", "0"),

  // ✅ CORS: mantengo string para compat + agrego array útil
  // Nota: tu index.ts hoy usa origin:true, esto es solo para tenerlo listo.
  CORS_ORIGIN: isProd ? must("CORS_ORIGIN") : opt("CORS_ORIGIN", "http://localhost:5173"),
  CORS_ORIGINS: isProd ? optCsv("CORS_ORIGIN", "") : optCsv("CORS_ORIGIN", "http://localhost:5173"),

  // ✅ Manteniendo nombre de BD (por ahora NO se toca)
  DATABASE_URL: must(
    "DATABASE_URL",
    isProd ? undefined : "mysql://root:.-p3nt4k1lL@localhost:3306/rafc_reload"
  ),
} as const;
