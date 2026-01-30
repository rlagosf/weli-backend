// src/gabriela/repos.ts
import { db } from "../db";
import type {
  CasoMedico,
  CrearCasoInput,
  ExamenMedico,
  Observacion,
  ResultadoLaboratorio,
  SubirExamenInput,
} from "./types";

export async function crearCaso(
  input: CrearCasoInput & { creado_por: number; id_estado_caso?: number }
): Promise<number> {
  const {
    rut_jugador,
    creado_por,
    motivo = null,
    fecha_inicio = null,
    id_estado_caso = 1,
  } = input;

  const [res]: any = await db.query(
    `
    INSERT INTO med_casos
      (rut_jugador, creado_por, motivo, id_estado_caso, fecha_inicio)
    VALUES
      (?, ?, ?, ?, ?)
    `,
    [rut_jugador, creado_por, motivo, id_estado_caso, fecha_inicio]
  );

  return Number(res.insertId);
}

export async function obtenerCasoPorId(id_caso: number): Promise<CasoMedico | null> {
  const [rows]: any = await db.query(
    `SELECT * FROM med_casos WHERE id = ? LIMIT 1`,
    [id_caso]
  );
  return rows?.[0] ?? null;
}

export async function listarExamenesPorCaso(id_caso: number): Promise<ExamenMedico[]> {
  const [rows]: any = await db.query(
    `SELECT * FROM med_examenes WHERE id_caso = ? ORDER BY creado_en DESC`,
    [id_caso]
  );
  return rows ?? [];
}

export async function listarObservacionesPorCaso(id_caso: number): Promise<Observacion[]> {
  const [rows]: any = await db.query(
    `SELECT * FROM med_observaciones WHERE id_caso = ? ORDER BY creado_en DESC`,
    [id_caso]
  );
  return rows ?? [];
}

export async function crearExamen(
  input: SubirExamenInput & {
    creado_por: number;
    hash_sha256: string;
    contenido_base64_limpio: string;
    id_estado_archivo?: number;
  }
): Promise<number> {
  const {
    id_caso,
    id_fuente_examen = 1,
    tipo_examen,
    fecha_examen = null,
    laboratorio = null,
    nombre_archivo = null,
    mime,
    hash_sha256,
    contenido_base64_limpio,
    creado_por,
    id_estado_archivo = 1,
  } = input;

  const [res]: any = await db.query(
    `
    INSERT INTO med_examenes
      (id_caso, id_fuente_examen, tipo_examen, fecha_examen, laboratorio,
       nombre_archivo, mime, hash_sha256, contenido_base64,
       id_estado_archivo, mensaje_error,
       creado_por)
    VALUES
      (?, ?, ?, ?, ?,
       ?, ?, ?, ?,
       ?, NULL,
       ?)
    `,
    [
      id_caso,
      id_fuente_examen,
      tipo_examen,
      fecha_examen,
      laboratorio,
      nombre_archivo,
      mime,
      hash_sha256,
      contenido_base64_limpio,
      id_estado_archivo,
      creado_por,
    ]
  );

  return Number(res.insertId);
}

export async function obtenerExamenPorId(id_examen: number): Promise<ExamenMedico | null> {
  const [rows]: any = await db.query(
    `SELECT * FROM med_examenes WHERE id = ? LIMIT 1`,
    [id_examen]
  );
  return rows?.[0] ?? null;
}

export async function actualizarEstadoExamen(
  id_examen: number,
  id_estado_archivo: number,
  mensaje_error: string | null = null
): Promise<void> {
  await db.query(
    `
    UPDATE med_examenes
    SET id_estado_archivo = ?, mensaje_error = ?, actualizado_en = NOW()
    WHERE id = ?
    `,
    [id_estado_archivo, mensaje_error, id_examen]
  );
}

export async function eliminarResultadosPorExamen(id_examen: number): Promise<void> {
  await db.query(`DELETE FROM med_resultados_laboratorio WHERE id_examen = ?`, [
    id_examen,
  ]);
}

export async function insertarResultadosBulk(
  id_examen: number,
  resultados: ResultadoLaboratorio[]
): Promise<number> {
  if (!resultados.length) return 0;

  const values = resultados.map((r) => [
    id_examen,
    r.codigo_analito,
    r.nombre_analito,
    r.valor_numerico,
    r.valor_texto,
    r.unidad,
    r.ref_min,
    r.ref_max,
    r.id_bandera,
    r.confianza,
    r.evidencia_textual,
  ]);

  const [res]: any = await db.query(
    `
    INSERT INTO med_resultados_laboratorio
      (id_examen, codigo_analito, nombre_analito,
       valor_numerico, valor_texto, unidad,
       ref_min, ref_max, id_bandera,
       confianza, evidencia_textual)
    VALUES ?
    `,
    [values]
  );

  return Number(res.affectedRows ?? 0);
}

export async function listarResultadosPorExamen(
  id_examen: number
): Promise<ResultadoLaboratorio[]> {
  const [rows]: any = await db.query(
    `
    SELECT *
    FROM med_resultados_laboratorio
    WHERE id_examen = ?
    ORDER BY nombre_analito ASC
    `,
    [id_examen]
  );
  return rows ?? [];
}

export async function crearObservacion(
  input: { id_caso: number; id_severidad: number; texto: string; creado_por: number }
): Promise<number> {
  const { id_caso, id_severidad, texto, creado_por } = input;

  const [res]: any = await db.query(
    `
    INSERT INTO med_observaciones
      (id_caso, id_severidad, texto, creado_por)
    VALUES
      (?, ?, ?, ?)
    `,
    [id_caso, id_severidad, texto, creado_por]
  );

  return Number(res.insertId);
}
