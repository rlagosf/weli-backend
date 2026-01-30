// src/schemas/schemas.ts
import { FastifyInstance } from "fastify";

/* ───────────────────────────────────────────────
   🔷 UTILIDADES BASE: Reutilizables en toda la API
─────────────────────────────────────────────── */

const Pagination = {
  type: "object",
  properties: {
    limit: { type: "integer" },
    offset: { type: "integer" },
    total: { type: "integer" },
  },
} as const;

const OkOnly = {
  $id: "OkOnly",
  type: "object",
  properties: { ok: { type: "boolean" } },
  required: ["ok"],
} as const;

/* ───────────────────────────────────────────────
   🔶 CATÁLOGOS (id + nombre)  ✅
─────────────────────────────────────────────── */

const CatalogoItem = {
  $id: "CatalogoItem",
  type: "object",
  properties: {
    id: { type: "integer" },
    nombre: { type: "string" },
  },
  required: ["id", "nombre"],
} as const;

const CatalogoListResponse = {
  $id: "CatalogoListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    items: { type: "array", items: { $ref: "CatalogoItem#" } },
  },
  required: ["ok", "items"],
} as const;

/* ───────────────────────────────────────────────
   🔶 JUGADORES
─────────────────────────────────────────────── */

const Jugador = {
  $id: "Jugador",
  type: "object",
  properties: {
    id: { type: "integer" },

    rut_jugador: { type: "string" },
    nombre_jugador: { type: "string" },

    edad: { type: ["integer", "null"] },
    email: { type: ["string", "null"] },
    telefono: { type: ["string", "null"] },
    direccion: { type: ["string", "null"] },
    comuna_id: { type: ["integer", "null"] },

    peso: { type: ["number", "null"] },
    estatura: { type: ["number", "null"] },

    talla_polera: { type: ["string", "null"] },
    talla_short: { type: ["string", "null"] },

    nombre_apoderado: { type: ["string", "null"] },
    rut_apoderado: { type: ["string", "null"] },
    telefono_apoderado: { type: ["string", "null"] },

    posicion_id: { type: ["integer", "null"] },
    categoria_id: { type: ["integer", "null"] },
    establec_educ_id: { type: ["integer", "null"] },
    prevision_medica_id: { type: ["integer", "null"] },
    estado_id: { type: ["integer", "null"] },
    sucursal_id: { type: ["integer", "null"] },

    estadistica_id: { type: ["integer", "null"] },

    observaciones: { type: ["string", "null"] },
    fecha_nacimiento: { type: ["string", "null"], format: "date" },
  },
  required: ["id", "nombre_jugador", "rut_jugador"],
} as const;

const JugadorListResponse = {
  $id: "JugadorListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    items: { type: "array", items: { $ref: "Jugador#" } },
    ...Pagination.properties,
  },
  required: ["ok", "items"],
} as const;

/* ───────────────────────────────────────────────
   🔶 PAGOS JUGADOR
─────────────────────────────────────────────── */

const PagoJugador = {
  $id: "PagoJugador",
  type: "object",
  properties: {
    id: { type: "integer" },

    jugador_rut: { type: "string" },
    tipo_pago_id: { type: "integer" },
    situacion_pago_id: { type: "integer" },

    monto: { type: "number" },
    fecha_pago: { type: "string", format: "date" },

    medio_pago_id: { type: "integer" },

    comprobante_url: { type: ["string", "null"] },
    observaciones: { type: ["string", "null"] },
  },
  required: [
    "id",
    "jugador_rut",
    "tipo_pago_id",
    "situacion_pago_id",
    "monto",
    "fecha_pago",
    "medio_pago_id",
  ],
} as const;

const PagoJugadorListResponse = {
  $id: "PagoJugadorListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    items: { type: "array", items: { $ref: "PagoJugador#" } },
  },
  required: ["ok", "items"],
} as const;

/* ───────────────────────────────────────────────
   🔶 ESTADÍSTICAS (dinámico)
─────────────────────────────────────────────── */

const Estadistica = {
  $id: "Estadistica",
  type: "object",
  additionalProperties: { type: ["integer", "number", "string", "null"] },
} as const;

const EstadisticaResponse = {
  $id: "EstadisticaResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    items: { type: "array", items: { $ref: "Estadistica#" } },
  },
  required: ["ok", "items"],
} as const;

/* ───────────────────────────────────────────────
   📰 NOTICIAS + ESTADO_NOTICIAS
─────────────────────────────────────────────── */

const EstadoNoticia = {
  $id: "EstadoNoticia",
  type: "object",
  properties: {
    id: { type: "integer" },
    nombre: { type: "string" },
  },
  required: ["id", "nombre"],
} as const;

const EstadoNoticiaListResponse = {
  $id: "EstadoNoticiaListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    items: { type: "array", items: { $ref: "EstadoNoticia#" } },
  },
  required: ["ok", "items"],
} as const;

const NoticiaListItem = {
  $id: "NoticiaListItem",
  type: "object",
  properties: {
    id: { type: "integer" },
    slug: { type: "string" },
    titulo: { type: "string" },
    resumen: { type: ["string", "null"] },

    imagen_mime: { type: ["string", "null"] },
    imagen_bytes: { type: ["integer", "string", "null"] },

    estado_noticia_id: { type: "integer" },
    estado_nombre: { type: "string" },

    published_at: { type: ["string", "null"] },

    is_popup: { type: ["integer", "boolean"] },
    popup_start_at: { type: ["string", "null"] },
    popup_end_at: { type: ["string", "null"] },

    pinned: { type: ["integer", "boolean"] },
    pinned_order: { type: ["integer", "string", "null"] },

    created_at: { type: "string" },
    updated_at: { type: "string" },
  },
  required: ["id", "slug", "titulo", "estado_noticia_id", "estado_nombre", "created_at", "updated_at"],
} as const;

const NoticiaListResponse = {
  $id: "NoticiaListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    items: { type: "array", items: { $ref: "NoticiaListItem#" } },
    ...Pagination.properties,
  },
  required: ["ok", "items"],
} as const;

const NoticiaDetail = {
  $id: "NoticiaDetail",
  type: "object",
  properties: {
    id: { type: "integer" },
    slug: { type: "string" },
    titulo: { type: "string" },
    resumen: { type: ["string", "null"] },
    contenido: { type: ["string", "null"] },

    imagen_mime: { type: ["string", "null"] },
    imagen_base64: { type: ["string", "null"] },
    imagen_bytes: { type: ["integer", "string", "null"] },

    estado_noticia_id: { type: "integer" },
    estado_nombre: { type: "string" },

    published_at: { type: ["string", "null"] },

    is_popup: { type: ["integer", "boolean"] },
    popup_start_at: { type: ["string", "null"] },
    popup_end_at: { type: ["string", "null"] },

    pinned: { type: ["integer", "boolean"] },
    pinned_order: { type: ["integer", "string", "null"] },

    created_by_admin_id: { type: ["integer", "null"] },

    created_at: { type: "string" },
    updated_at: { type: "string" },
  },
  required: ["id", "slug", "titulo", "estado_noticia_id", "estado_nombre", "created_at", "updated_at"],
} as const;

const NoticiaDetailResponse = {
  $id: "NoticiaDetailResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    item: { $ref: "NoticiaDetail#" },
  },
  required: ["ok", "item"],
} as const;

/* ───────────────────────────────────────────────
   📌 REGISTRAR SCHEMAS
─────────────────────────────────────────────── */

export async function registerSchemas(app: FastifyInstance) {
  // Utilidades
  app.addSchema(OkOnly);

  // Catálogos
  app.addSchema(CatalogoItem);
  app.addSchema(CatalogoListResponse);

  // Jugadores
  app.addSchema(Jugador);
  app.addSchema(JugadorListResponse);

  // Pagos
  app.addSchema(PagoJugador);
  app.addSchema(PagoJugadorListResponse);

  // Estadísticas
  app.addSchema(Estadistica);
  app.addSchema(EstadisticaResponse);

  // Noticias
  app.addSchema(EstadoNoticia);
  app.addSchema(EstadoNoticiaListResponse);

  app.addSchema(NoticiaListItem);
  app.addSchema(NoticiaListResponse);

  app.addSchema(NoticiaDetail);
  app.addSchema(NoticiaDetailResponse);
}
