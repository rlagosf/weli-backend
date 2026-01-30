// src/gabriela/services.ts
import crypto from "crypto";
import type {
  CrearCasoInput,
  ProcesarExamenResultado,
  SubirExamenInput,
  TipoUsuarioRequest,
} from "./types";
import * as repos from "./repos";

/**
 * ✅ Deriva el subtipo admin desde la unión TipoUsuarioRequest
 * sin depender de "UsuarioAdmin" en types.ts
 */
type UsuarioAdmin = Extract<TipoUsuarioRequest, { type: "admin" }>;

/**
 * ✅ Type guard (asserts) para que TS entienda que luego de esto user ES admin
 * y por tanto existe user.id.
 */
function asegurarAdmin(user: TipoUsuarioRequest): asserts user is UsuarioAdmin {
  if (!user || user.type !== "admin") {
    const err: any = new Error("Acceso denegado: solo staff/admin.");
    err.statusCode = 403;
    throw err;
  }
}

/**
 * Limpia base64:
 * - acepta base64 puro
 * - acepta data URL: data:application/pdf;base64,XXXX
 */
function limpiarBase64(input: string): string {
  const s = String(input ?? "").trim();
  const idx = s.indexOf("base64,");
  return idx >= 0 ? s.substring(idx + "base64,".length).trim() : s;
}

/**
 * Valida tamaño aproximado para evitar payloads gigantes.
 * bytes ≈ (len * 3/4) - padding
 */
function validarTamanioBase64(base64: string, maxMB = 12) {
  const len = base64.length;
  const padding = base64.endsWith("==") ? 2 : base64.endsWith("=") ? 1 : 0;
  const bytes = Math.floor((len * 3) / 4) - padding;

  const maxBytes = maxMB * 1024 * 1024;
  if (bytes > maxBytes) {
    const err: any = new Error(
      `Archivo demasiado grande. Máximo ${maxMB} MB (aprox).`
    );
    err.statusCode = 413;
    throw err;
  }
}

/**
 * Validación mínima de base64 para detectar payload roto
 * (no pretende ser perfecta, pero evita lo más común).
 */
function validarFormatoBase64(base64: string) {
  if (!base64 || base64.length < 16) {
    const err: any = new Error("contenido_base64 inválido o vacío.");
    err.statusCode = 400;
    throw err;
  }

  // Caracteres típicos base64 (permitimos espacios por si viene con saltos)
  const ok = /^[A-Za-z0-9+/=\s]+$/.test(base64);
  if (!ok) {
    const err: any = new Error("contenido_base64 contiene caracteres inválidos.");
    err.statusCode = 400;
    throw err;
  }

  // Probamos decodificar (si revienta, es inválido)
  try {
    Buffer.from(base64, "base64");
  } catch {
    const err: any = new Error("contenido_base64 no se puede decodificar.");
    err.statusCode = 400;
    throw err;
  }
}

/**
 * MIME permitido en v1 (ajústalo si quieres)
 */
function validarMime(mime: string) {
  const m = String(mime ?? "").trim().toLowerCase();

  const permitidos = new Set([
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/jpg",
    "image/webp",
  ]);

  if (!permitidos.has(m)) {
    const err: any = new Error(
      `mime no permitido. Permitidos: ${Array.from(permitidos).join(", ")}`
    );
    err.statusCode = 415;
    throw err;
  }
}

function sha256DeBase64(base64: string): string {
  const buf = Buffer.from(base64, "base64");
  return crypto.createHash("sha256").update(buf).digest("hex");
}

/* ─────────────────────────────
   Casos
───────────────────────────── */

export async function crearCaso(user: TipoUsuarioRequest, input: CrearCasoInput) {
  asegurarAdmin(user);

  const id_caso = await repos.crearCaso({
    ...input,
    creado_por: user.id,
    id_estado_caso: 1, // abierto
  });

  const caso = await repos.obtenerCasoPorId(id_caso);
  return { ok: true, caso };
}

export async function obtenerCasoDetalle(user: TipoUsuarioRequest, id_caso: number) {
  asegurarAdmin(user);

  const caso = await repos.obtenerCasoPorId(id_caso);
  if (!caso) {
    const err: any = new Error("Caso no encontrado.");
    err.statusCode = 404;
    throw err;
  }

  const examenes = await repos.listarExamenesPorCaso(id_caso);
  const observaciones = await repos.listarObservacionesPorCaso(id_caso);

  return { ok: true, caso, examenes, observaciones };
}

/* ─────────────────────────────
   Exámenes
───────────────────────────── */

export async function subirExamen(user: TipoUsuarioRequest, input: SubirExamenInput) {
  asegurarAdmin(user);

  // Validar mime (evita que te manden cualquier cosa)
  validarMime(input.mime);

  // Limpiar base64 (dataURL -> puro)
  const base64Limpio = limpiarBase64(input.contenido_base64);

  // Validaciones de seguridad/estabilidad
  validarFormatoBase64(base64Limpio);
  validarTamanioBase64(base64Limpio, 12);

  const hash = sha256DeBase64(base64Limpio);

  // Validar que caso exista
  const caso = await repos.obtenerCasoPorId(input.id_caso);
  if (!caso) {
    const err: any = new Error("Caso no encontrado para id_caso indicado.");
    err.statusCode = 404;
    throw err;
  }

  // Insert examen
  const id_examen = await repos.crearExamen({
    ...input,
    creado_por: user.id,
    hash_sha256: hash,
    contenido_base64_limpio: base64Limpio,
    id_estado_archivo: 1, // subido
  });

  const examen = await repos.obtenerExamenPorId(id_examen);
  return { ok: true, examen };
}

/**
 * Procesamiento v0:
 * - Estado: subido(1) -> procesando(2) -> procesado(3) o error(4)
 * - En v1 real se reemplaza por pipeline OCR/parser
 */
export async function procesarExamen(
  user: TipoUsuarioRequest,
  id_examen: number
): Promise<ProcesarExamenResultado> {
  asegurarAdmin(user);

  const examen = await repos.obtenerExamenPorId(id_examen);
  if (!examen) {
    const err: any = new Error("Examen no encontrado.");
    err.statusCode = 404;
    throw err;
  }

  // Estado -> procesando
  await repos.actualizarEstadoExamen(id_examen, 2, null);

  try {
    // Reprocesamiento: limpiar resultados previos
    await repos.eliminarResultadosPorExamen(id_examen);

    // Aquí luego llamaremos a pipeline/procesar_examen.ts
    // Por ahora: no insertamos resultados (v0)
    const insertados = await repos.insertarResultadosBulk(id_examen, []);

    // Estado -> procesado
    await repos.actualizarEstadoExamen(id_examen, 3, null);

    // Observación de sistema (evita “silencio”)
    await repos.crearObservacion({
      id_caso: examen.id_caso,
      id_severidad: 1, // info
      texto:
        "Procesamiento v1 pendiente: el examen fue almacenado y marcado como procesado, pero el pipeline OCR/parser aún no está habilitado.",
      creado_por: user.id,
    });

    return {
      ok: true,
      id_examen,
      id_estado_archivo: 3,
      resultados_insertados: insertados,
    };
  } catch (e: any) {
    await repos.actualizarEstadoExamen(
      id_examen,
      4,
      e?.message ? String(e.message) : "Error desconocido en procesamiento"
    );
    throw e;
  }
}

export async function obtenerResultados(user: TipoUsuarioRequest, id_examen: number) {
  asegurarAdmin(user);

  const examen = await repos.obtenerExamenPorId(id_examen);
  if (!examen) {
    const err: any = new Error("Examen no encontrado.");
    err.statusCode = 404;
    throw err;
  }

  const resultados = await repos.listarResultadosPorExamen(id_examen);
  return { ok: true, examen, resultados };
}
