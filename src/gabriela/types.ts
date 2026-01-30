// src/gabriela/types.ts

export type TipoUsuarioRequest =
  | { type: "admin"; id: number; rol_id: number; nombre_usuario?: string }
  | { type: "apoderado"; rut: string };

export type CasoMedico = {
  id: number;
  rut_jugador: number | null;
  creado_por: number;
  motivo: string | null;
  id_estado_caso: number;
  fecha_inicio: string | null; // DATE -> string YYYY-MM-DD
  fecha_cierre: string | null;
  creado_en: string; // DATETIME -> string ISO-like
  actualizado_en: string;
};

export type ExamenMedico = {
  id: number;
  id_caso: number;
  id_fuente_examen: number;
  tipo_examen: string;
  fecha_examen: string | null;
  laboratorio: string | null;

  nombre_archivo: string | null;
  mime: string;
  hash_sha256: string;
  contenido_base64: string;

  id_estado_archivo: number;
  mensaje_error: string | null;

  creado_por: number;
  creado_en: string;
  actualizado_en: string;
};

export type ResultadoLaboratorio = {
  id?: number;
  id_examen: number;
  codigo_analito: string;
  nombre_analito: string;
  valor_numerico: number | null;
  valor_texto: string | null;
  unidad: string | null;
  ref_min: number | null;
  ref_max: number | null;
  id_bandera: number; // 1=bajo 2=alto 3=normal 4=anormal
  confianza: number; // 0..1
  evidencia_textual: string | null;
};

export type Observacion = {
  id?: number;
  id_caso: number;
  id_severidad: number; // 1=info..5=critica
  texto: string;
  creado_por: number;
  creado_en?: string;
};

export type CrearCasoInput = {
  rut_jugador: number | null;
  motivo?: string | null;
  fecha_inicio?: string | null; // YYYY-MM-DD
};

export type SubirExamenInput = {
  id_caso: number;
  id_fuente_examen?: number; // default 1
  tipo_examen: string;
  fecha_examen?: string | null;
  laboratorio?: string | null;

  nombre_archivo?: string | null;
  mime: string;

  // base64 puro (sin data:...) o dataURL (lo limpiamos en service)
  contenido_base64: string;
};

export type ProcesarExamenResultado = {
  ok: true;
  id_examen: number;
  id_estado_archivo: number;
  resultados_insertados: number;
};
