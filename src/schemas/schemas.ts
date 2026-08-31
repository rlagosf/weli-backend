// src/schemas/schemas.ts

import type { FastifyInstance } from "fastify";

/* =========================================================
   UTILIDADES BASE
========================================================= */

const OkOnly = {
  $id: "OkOnly",
  type: "object",
  properties: {
    ok: { type: "boolean" },
  },
  required: ["ok"],
} as const;

const ErrorResponse = {
  $id: "ErrorResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    message: { type: "string" },
    detail: { type: ["string", "null"] },
  },
  required: ["ok", "message"],
} as const;

const DeleteResponse = {
  $id: "DeleteResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    deleted: { type: "integer" },
  },
  required: ["ok", "deleted"],
} as const;

const HealthResponse = {
  $id: "HealthResponse",
  type: "object",
  properties: {
    module: { type: "string" },
    status: { type: "string" },
    academia_id: { type: ["integer", "null"] },
    timestamp: { type: "string" },
  },
  required: ["module", "status", "timestamp"],
} as const;

/*
 * Respuestas reutilizables de seguridad.
 *
 * IMPORTANTE:
 * Estos schemas DOCUMENTAN las respuestas.
 * La seguridad real sigue siendo:
 *
 * requireAuth
 * requireRoles(...)
 * getEffectiveAcademiaId(...)
 */
const UnauthorizedResponse = {
  $id: "UnauthorizedResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    message: { type: "string" },
  },
  required: ["ok", "message"],
} as const;

const ForbiddenResponse = {
  $id: "ForbiddenResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    message: { type: "string" },
  },
  required: ["ok", "message"],
} as const;

/* =========================================================
   BASE CATÁLOGOS
========================================================= */

const CatalogoItem = {
  $id: "CatalogoItem",
  type: "object",
  properties: {
    id: { type: "integer" },
    nombre: { type: "string" },
  },
  required: ["id", "nombre"],
} as const;

const CatalogoTenantItem = {
  $id: "CatalogoTenantItem",
  type: "object",
  properties: {
    id: { type: "integer" },
    academia_id: { type: ["integer", "null"] },
    nombre: { type: "string" },
  },
  required: ["id", "nombre"],
} as const;

const CatalogoListResponse = {
  $id: "CatalogoListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: {
      type: "array",
      items: { $ref: "CatalogoItem#" },
    },
  },
  required: ["ok", "items"],
} as const;

const CatalogoTenantListResponse = {
  $id: "CatalogoTenantListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: {
      type: "array",
      items: { $ref: "CatalogoTenantItem#" },
    },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   01. CATEGORÍAS
========================================================= */

const Categoria = {
  $id: "Categoria",
  type: "object",
  properties: {
    id: { type: "integer" },
    nombre: { type: "string" },
  },
  required: ["id", "nombre"],
} as const;

const CategoriaListResponse = {
  $id: "CategoriaListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: { type: "array", items: { $ref: "Categoria#" } },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   02. COMUNAS
========================================================= */

const Comuna = {
  $id: "Comuna",
  type: "object",
  properties: {
    id: { type: "integer" },
    nombre: { type: "string" },
  },
  required: ["id", "nombre"],
} as const;

const ComunaListResponse = {
  $id: "ComunaListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: { type: "array", items: { $ref: "Comuna#" } },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   03. DEPORTES
========================================================= */

const Deporte = {
  $id: "Deporte",
  type: "object",
  properties: {
    id: { type: "integer" },
    nombre: { type: "string" },
  },
  required: ["id", "nombre"],
} as const;

const DeporteListResponse = {
  $id: "DeporteListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: { type: "array", items: { $ref: "Deporte#" } },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   04. ESTABLECIMIENTOS EDUCACIONALES
========================================================= */

const EstablecimientoEducacional = {
  $id: "EstablecimientoEducacional",
  type: "object",
  properties: {
    id: { type: "integer" },
    nombre: { type: "string" },
  },
  required: ["id", "nombre"],
} as const;

const EstablecimientoEducacionalListResponse = {
  $id: "EstablecimientoEducacionalListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: {
      type: "array",
      items: { $ref: "EstablecimientoEducacional#" },
    },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   05. ESTADO
========================================================= */

const Estado = {
  $id: "Estado",
  type: "object",
  properties: {
    id: { type: "integer" },
    nombre: { type: "string" },
  },
  required: ["id", "nombre"],
} as const;

const EstadoListResponse = {
  $id: "EstadoListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: { type: "array", items: { $ref: "Estado#" } },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   06. MEDIOS DE PAGO
========================================================= */

const MedioPago = {
  $id: "MedioPago",
  type: "object",
  properties: {
    id: { type: "integer" },
    academia_id: { type: "integer" },
    nombre: { type: "string" },
  },
  required: ["id", "academia_id", "nombre"],
} as const;

const MedioPagoListResponse = {
  $id: "MedioPagoListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: { type: "array", items: { $ref: "MedioPago#" } },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   07. POSICIONES
========================================================= */

const Posicion = {
  $id: "Posicion",
  type: "object",
  properties: {
    id: { type: "integer" },
    nombre: { type: "string" },
  },
  required: ["id", "nombre"],
} as const;

const PosicionListResponse = {
  $id: "PosicionListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: { type: "array", items: { $ref: "Posicion#" } },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   08. PREVISIÓN MÉDICA
========================================================= */

const PrevisionMedica = {
  $id: "PrevisionMedica",
  type: "object",
  properties: {
    id: { type: "integer" },
    nombre: { type: "string" },
  },
  required: ["id", "nombre"],
} as const;

const PrevisionMedicaListResponse = {
  $id: "PrevisionMedicaListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: { type: "array", items: { $ref: "PrevisionMedica#" } },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   09. ROLES
========================================================= */

const Rol = {
  $id: "Rol",
  type: "object",
  properties: {
    id: { type: "integer" },
    nombre: { type: "string" },
  },
  required: ["id", "nombre"],
} as const;

const RolListResponse = {
  $id: "RolListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: { type: "array", items: { $ref: "Rol#" } },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   10. SITUACIÓN DE PAGO
========================================================= */

const SituacionPago = {
  $id: "SituacionPago",
  type: "object",
  properties: {
    id: { type: "integer" },
    nombre: { type: "string" },
  },
  required: ["id", "nombre"],
} as const;

const SituacionPagoListResponse = {
  $id: "SituacionPagoListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: { type: "array", items: { $ref: "SituacionPago#" } },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   11. SUCURSALES
========================================================= */

const SucursalReal = {
  $id: "SucursalReal",
  type: "object",
  properties: {
    id: { type: "integer" },
    academia_id: { type: "integer" },
    nombre: { type: "string" },
  },
  required: ["id", "academia_id", "nombre"],
} as const;

const SucursalRealListResponse = {
  $id: "SucursalRealListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: { type: "array", items: { $ref: "SucursalReal#" } },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   12. TIPO DE PAGO
========================================================= */

const TipoPago = {
  $id: "TipoPago",
  type: "object",
  properties: {
    id: { type: "integer" },

    /*
     * Se mantiene nullable porque el modelo histórico
     * permite tipos de pago globales.
     */
    academia_id: { type: ["integer", "null"] },

    nombre: { type: "string" },
  },
  required: ["id", "nombre"],
} as const;

const TipoPagoListResponse = {
  $id: "TipoPagoListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: { type: "array", items: { $ref: "TipoPago#" } },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   13. USUARIOS
   Contrato conservador hasta enlazarlo al router.
========================================================= */

const Usuario = {
  $id: "Usuario",
  type: "object",

  properties: {
    id: { type: "integer" },
    academia_id: { type: ["integer", "null"] },

    username: { type: ["string", "null"] },
    nombre: { type: ["string", "null"] },
    email: { type: ["string", "null"] },

    rol_id: { type: ["integer", "null"] },
    estado_id: { type: ["integer", "null"] },

    created_at: { type: ["string", "null"] },
    updated_at: { type: ["string", "null"] },
  },

  /*
   * Importante:
   * Nunca incluir password_hash/password.
   */
  required: ["id"],
  additionalProperties: true,
} as const;

const UsuarioListResponse = {
  $id: "UsuarioListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: { type: "array", items: { $ref: "Usuario#" } },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   14. EVENTOS
   Flexible para no inventar el contrato del router actual.
========================================================= */

const Evento = {
  $id: "Evento",
  type: "object",
  properties: {
    id: { type: "integer" },
    academia_id: { type: ["integer", "null"] },

    nombre: { type: ["string", "null"] },
    titulo: { type: ["string", "null"] },
    descripcion: { type: ["string", "null"] },

    fecha: { type: ["string", "null"] },
    fecha_inicio: { type: ["string", "null"] },
    fecha_fin: { type: ["string", "null"] },

    estado_id: { type: ["integer", "null"] },

    created_at: { type: ["string", "null"] },
    updated_at: { type: ["string", "null"] },
  },
  required: ["id"],
  additionalProperties: true,
} as const;

const EventoListResponse = {
  $id: "EventoListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: { type: "array", items: { $ref: "Evento#" } },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   15. CONVOCATORIAS
========================================================= */

const Convocatoria = {
  $id: "Convocatoria",
  type: "object",
  properties: {
    id: { type: "integer" },
    academia_id: { type: ["integer", "null"] },

    jugador_id: { type: ["integer", "null"] },
    evento_id: { type: ["integer", "null"] },

    estado_id: { type: ["integer", "null"] },

    created_at: { type: ["string", "null"] },
    updated_at: { type: ["string", "null"] },
  },
  required: ["id"],
  additionalProperties: true,
} as const;

const ConvocatoriaListResponse = {
  $id: "ConvocatoriaListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: { type: "array", items: { $ref: "Convocatoria#" } },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   16. CONVOCATORIAS HISTÓRICAS
========================================================= */

const ConvocatoriaHistorico = {
  $id: "ConvocatoriaHistorico",
  type: "object",
  properties: {
    id: { type: "integer" },
    academia_id: { type: ["integer", "null"] },

    jugador_id: { type: ["integer", "null"] },
    evento_id: { type: ["integer", "null"] },

    created_at: { type: ["string", "null"] },
    updated_at: { type: ["string", "null"] },
  },
  required: ["id"],
  additionalProperties: true,
} as const;

const ConvocatoriaHistoricoListResponse = {
  $id: "ConvocatoriaHistoricoListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: {
      type: "array",
      items: { $ref: "ConvocatoriaHistorico#" },
    },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   17. AUTH USER
========================================================= */

const AuthUser = {
  $id: "AuthUser",
  type: "object",

  properties: {
    id: { type: "integer" },
    username: { type: ["string", "null"] },

    rol_id: { type: "integer" },

    /*
     * Superadmin puede no tener academia firmada.
     */
    academia_id: { type: ["integer", "null"] },
  },

  required: ["id", "rol_id"],

  /*
   * Nunca incluir:
   * password
   * password_hash
   * argon_hash
   */
  additionalProperties: true,
} as const;

/* =========================================================
   18. AUTH RESPONSE
========================================================= */

const AuthResponse = {
  $id: "AuthResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    token: { type: "string" },
    user: { $ref: "AuthUser#" },
  },
  required: ["ok", "token", "user"],
  additionalProperties: true,
} as const;

/* =========================================================
   19. AUTH APODERADO RESPONSE
   Flexible hasta cotejar auth_apoderado.ts.
========================================================= */

const AuthApoderadoResponse = {
  $id: "AuthApoderadoResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    token: { type: "string" },
    user: {
      type: ["object", "null"],
      additionalProperties: true,
    },
  },
  required: ["ok"],
  additionalProperties: true,
} as const;

/* =========================================================
   20. PORTAL APODERADO
   Modelo conservador.
========================================================= */

const PortalApoderado = {
  $id: "PortalApoderado",
  type: "object",
  properties: {
    ok: { type: "boolean" },
  },
  required: ["ok"],
  additionalProperties: true,
} as const;

/* =========================================================
   ACADEMIAS
========================================================= */

const Academia = {
  $id: "Academia",
  type: "object",
  properties: {
    id: { type: "integer" },
    nombre: { type: "string" },

    /*
     * El RUT numérico se mantiene como INT.
     * El DV se calcula separadamente en frontend.
     */
    rut_academia: { type: ["integer", "null"] },

    deporte_id: { type: "integer" },
    estado_id: { type: "integer" },

    deporte_nombre: { type: ["string", "null"] },
    estado_nombre: { type: ["string", "null"] },

    created_at: { type: ["string", "null"] },
    updated_at: { type: ["string", "null"] },
  },
  required: ["id", "nombre", "deporte_id", "estado_id"],
} as const;

const AcademiaListResponse = {
  $id: "AcademiaListResponse",
  type: "object",
  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },
    items: { type: "array", items: { $ref: "Academia#" } },
  },
  required: ["ok", "items"],
} as const;

/* =========================================================
   JUGADORES
========================================================= */

const Jugador = {
  $id: "Jugador",
  type: "object",

  properties: {
    id: { type: "integer" },

    academia_id: { type: "integer" },
    deporte_id: { type: ["integer", "null"] },

    rut_jugador: { type: "integer" },
    nombre_jugador: { type: "string" },

    fecha_nacimiento: {
      type: ["string", "null"],
      format: "date",
    },

    edad: { type: ["integer", "null"] },

    email: { type: ["string", "null"] },
    telefono: { type: ["string", "null"] },
    direccion: { type: ["string", "null"] },

    comuna_id: { type: ["integer", "null"] },
    posicion_id: { type: ["integer", "null"] },
    categoria_id: { type: ["integer", "null"] },

    establec_educ_id: { type: ["integer", "null"] },
    prevision_medica_id: { type: ["integer", "null"] },

    estado_id: { type: ["integer", "null"] },

    /*
     * Campo histórico.
     * La relación real N:M corresponde a jugador_sucursal.
     */
    sucursal_id: { type: ["integer", "null"] },

    peso: { type: ["number", "null"] },
    estatura: { type: ["number", "null"] },

    talla_polera: { type: ["string", "null"] },
    talla_short: { type: ["string", "null"] },

    nombre_apoderado: { type: ["string", "null"] },
    rut_apoderado: { type: ["integer", "null"] },
    telefono_apoderado: { type: ["string", "null"] },

    estadistica_id: { type: ["integer", "null"] },

    observaciones: { type: ["string", "null"] },

    created_at: { type: ["string", "null"] },
    updated_at: { type: ["string", "null"] },
  },

  required: ["id", "academia_id", "nombre_jugador", "rut_jugador"],
} as const;

const JugadorListResponse = {
  $id: "JugadorListResponse",
  type: "object",

  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },

    items: {
      type: "array",
      items: { $ref: "Jugador#" },
    },

    limit: { type: "integer" },
    offset: { type: "integer" },
    total: { type: "integer" },
  },

  required: ["ok", "items"],
} as const;

/* =========================================================
   PLANES
========================================================= */

const Plan = {
  $id: "Plan",
  type: "object",

  properties: {
    id: { type: "integer" },
    academia_id: { type: "integer" },

    nombre: { type: "string" },
    descripcion: { type: ["string", "null"] },

    periodicidad: { type: "string" },
    estado_id: { type: "integer" },

    created_at: { type: ["string", "null"] },
    updated_at: { type: ["string", "null"] },
  },

  required: ["id", "academia_id", "nombre", "periodicidad", "estado_id"],
} as const;

const PlanListResponse = {
  $id: "PlanListResponse",
  type: "object",

  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },

    items: {
      type: "array",
      items: { $ref: "Plan#" },
    },
  },

  required: ["ok", "items"],
} as const;

/* =========================================================
   PLAN ↔ SUCURSAL
========================================================= */

const PlanSucursal = {
  $id: "PlanSucursal",
  type: "object",

  properties: {
    id: { type: "integer" },

    academia_id: { type: "integer" },
    plan_id: { type: "integer" },
    sucursal_id: { type: "integer" },

    plan_nombre: { type: ["string", "null"] },
    sucursal_nombre: { type: ["string", "null"] },

    created_at: { type: ["string", "null"] },
  },

  required: ["id", "academia_id", "plan_id", "sucursal_id"],
} as const;

const PlanSucursalListResponse = {
  $id: "PlanSucursalListResponse",
  type: "object",

  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },

    items: {
      type: "array",
      items: { $ref: "PlanSucursal#" },
    },
  },

  required: ["ok", "items"],
} as const;

/* =========================================================
   PLAN TARIFAS
========================================================= */

const PlanTarifa = {
  $id: "PlanTarifa",
  type: "object",

  properties: {
    id: { type: "integer" },
    academia_id: { type: "integer" },

    plan_id: { type: "integer" },
    tipo_pago_id: { type: "integer" },

    nombre: { type: "string" },
    monto: { type: "number" },

    vigencia_desde: {
      type: "string",
      format: "date",
    },

    vigencia_hasta: {
      type: ["string", "null"],
      format: "date",
    },

    estado_id: { type: "integer" },

    plan_nombre: { type: ["string", "null"] },
    tipo_pago_nombre: { type: ["string", "null"] },

    created_at: { type: ["string", "null"] },
    updated_at: { type: ["string", "null"] },
  },

  required: ["id", "academia_id", "plan_id", "tipo_pago_id", "nombre", "monto", "vigencia_desde", "estado_id"],
} as const;

const PlanTarifaListResponse = {
  $id: "PlanTarifaListResponse",
  type: "object",

  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },

    items: {
      type: "array",
      items: { $ref: "PlanTarifa#" },
    },
  },

  required: ["ok", "items"],
} as const;

/* =========================================================
   TARIFA ↔ SUCURSAL
========================================================= */

const TarifaSucursal = {
  $id: "TarifaSucursal",
  type: "object",

  properties: {
    id: { type: "integer" },

    academia_id: { type: "integer" },
    tarifa_id: { type: "integer" },
    sucursal_id: { type: "integer" },

    tarifa_nombre: { type: ["string", "null"] },
    monto: { type: ["number", "null"] },

    vigencia_desde: {
      type: ["string", "null"],
      format: "date",
    },

    vigencia_hasta: {
      type: ["string", "null"],
      format: "date",
    },

    tarifa_estado_id: { type: ["integer", "null"] },

    plan_id: { type: ["integer", "null"] },
    plan_nombre: { type: ["string", "null"] },

    tipo_pago_id: { type: ["integer", "null"] },
    tipo_pago_nombre: { type: ["string", "null"] },

    sucursal_nombre: { type: ["string", "null"] },

    created_at: { type: ["string", "null"] },
  },

  required: ["id", "academia_id", "tarifa_id", "sucursal_id"],
} as const;

const TarifaSucursalListResponse = {
  $id: "TarifaSucursalListResponse",
  type: "object",

  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },

    items: {
      type: "array",
      items: { $ref: "TarifaSucursal#" },
    },
  },

  required: ["ok", "items"],
} as const;

/* =========================================================
   PROMOCIONES
========================================================= */

const Promocion = {
  $id: "Promocion",
  type: "object",

  properties: {
    id: { type: "integer" },
    academia_id: { type: "integer" },

    nombre: { type: "string" },
    descripcion: { type: ["string", "null"] },

    tipo_beneficio: {
      type: "string",
      enum: ["PORCENTAJE", "DESCUENTO_FIJO", "PRECIO_FIJO"],
    },

    valor: { type: "number" },

    fecha_desde: {
      type: "string",
      format: "date",
    },

    fecha_hasta: {
      type: ["string", "null"],
      format: "date",
    },

    estado_id: { type: "integer" },

    created_at: { type: ["string", "null"] },
    updated_at: { type: ["string", "null"] },
  },

  required: ["id", "academia_id", "nombre", "tipo_beneficio", "valor", "fecha_desde", "estado_id"],
} as const;

const PromocionListResponse = {
  $id: "PromocionListResponse",
  type: "object",

  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },

    items: {
      type: "array",
      items: { $ref: "Promocion#" },
    },
  },

  required: ["ok", "items"],
} as const;

/* =========================================================
   PROMOCIÓN ↔ PLAN
========================================================= */

const PromocionPlan = {
  $id: "PromocionPlan",
  type: "object",

  properties: {
    id: { type: "integer" },

    academia_id: { type: "integer" },
    promocion_id: { type: "integer" },
    plan_id: { type: "integer" },

    promocion_nombre: { type: ["string", "null"] },

    tipo_beneficio: {
      type: ["string", "null"],
      enum: ["PORCENTAJE", "DESCUENTO_FIJO", "PRECIO_FIJO", null],
    },

    valor: { type: ["number", "null"] },

    fecha_desde: {
      type: ["string", "null"],
      format: "date",
    },

    fecha_hasta: {
      type: ["string", "null"],
      format: "date",
    },

    promocion_estado_id: { type: ["integer", "null"] },

    plan_nombre: { type: ["string", "null"] },
    periodicidad: { type: ["string", "null"] },
    plan_estado_id: { type: ["integer", "null"] },

    created_at: { type: ["string", "null"] },
  },

  required: ["id", "academia_id", "promocion_id", "plan_id"],
} as const;

const PromocionPlanListResponse = {
  $id: "PromocionPlanListResponse",
  type: "object",

  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },

    items: {
      type: "array",
      items: { $ref: "PromocionPlan#" },
    },
  },

  required: ["ok", "items"],
} as const;

/* =========================================================
   PROMOCIÓN ↔ SUCURSAL
========================================================= */

const PromocionSucursal = {
  $id: "PromocionSucursal",
  type: "object",

  properties: {
    id: { type: "integer" },

    academia_id: { type: "integer" },
    promocion_id: { type: "integer" },
    sucursal_id: { type: "integer" },

    promocion_nombre: { type: ["string", "null"] },

    tipo_beneficio: {
      type: ["string", "null"],
    },

    valor: { type: ["number", "null"] },

    fecha_desde: {
      type: ["string", "null"],
      format: "date",
    },

    fecha_hasta: {
      type: ["string", "null"],
      format: "date",
    },

    promocion_estado_id: { type: ["integer", "null"] },

    sucursal_nombre: { type: ["string", "null"] },

    created_at: { type: ["string", "null"] },
  },

  required: ["id", "academia_id", "promocion_id", "sucursal_id"],
} as const;

const PromocionSucursalListResponse = {
  $id: "PromocionSucursalListResponse",
  type: "object",

  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },

    items: {
      type: "array",
      items: { $ref: "PromocionSucursal#" },
    },
  },

  required: ["ok", "items"],
} as const;

/* =========================================================
   PROMOCIÓN ↔ TIPO PAGO
========================================================= */

const PromocionTipoPago = {
  $id: "PromocionTipoPago",
  type: "object",

  properties: {
    id: { type: "integer" },

    academia_id: { type: "integer" },
    promocion_id: { type: "integer" },
    tipo_pago_id: { type: "integer" },

    promocion_nombre: { type: ["string", "null"] },
    tipo_beneficio: { type: ["string", "null"] },
    valor: { type: ["number", "null"] },

    fecha_desde: {
      type: ["string", "null"],
      format: "date",
    },

    fecha_hasta: {
      type: ["string", "null"],
      format: "date",
    },

    promocion_estado_id: { type: ["integer", "null"] },
    tipo_pago_nombre: { type: ["string", "null"] },

    created_at: { type: ["string", "null"] },
  },

  required: ["id", "academia_id", "promocion_id", "tipo_pago_id"],
} as const;

const PromocionTipoPagoListResponse = {
  $id: "PromocionTipoPagoListResponse",
  type: "object",

  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },

    items: {
      type: "array",
      items: { $ref: "PromocionTipoPago#" },
    },
  },

  required: ["ok", "items"],
} as const;

/* =========================================================
   JUGADOR ↔ PLAN
========================================================= */

const JugadorPlan = {
  $id: "JugadorPlan",
  type: "object",

  properties: {
    id: { type: "integer" },

    academia_id: { type: "integer" },
    jugador_id: { type: "integer" },
    plan_id: { type: "integer" },

    fecha_inicio: {
      type: "string",
      format: "date",
    },

    fecha_fin: {
      type: ["string", "null"],
      format: "date",
    },

    estado_id: { type: "integer" },

    jugador_nombre: { type: ["string", "null"] },
    jugador_rut: { type: ["integer", "null"] },

    plan_nombre: { type: ["string", "null"] },
    periodicidad: { type: ["string", "null"] },

    created_at: { type: ["string", "null"] },
    updated_at: { type: ["string", "null"] },
  },

  required: ["id", "academia_id", "jugador_id", "plan_id", "fecha_inicio", "estado_id"],
} as const;

const JugadorPlanListResponse = {
  $id: "JugadorPlanListResponse",
  type: "object",

  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },

    items: {
      type: "array",
      items: { $ref: "JugadorPlan#" },
    },
  },

  required: ["ok", "items"],
} as const;

/* =========================================================
   CARGOS JUGADOR
========================================================= */

const CargoJugador = {
  $id: "CargoJugador",
  type: "object",

  properties: {
    id: { type: "integer" },

    academia_id: { type: "integer" },
    sucursal_id: { type: "integer" },

    jugador_id: { type: "integer" },
    jugador_plan_id: { type: "integer" },

    tarifa_id: { type: "integer" },
    tipo_pago_id: { type: "integer" },

    promocion_id: {
      type: ["integer", "null"],
    },

    periodo_desde: {
      type: "string",
      format: "date",
    },

    periodo_hasta: {
      type: "string",
      format: "date",
    },

    fecha_vencimiento: {
      type: "string",
      format: "date",
    },

    monto_base: { type: "number" },
    monto_descuento: { type: "number" },
    monto_total: { type: "number" },

    situacion_pago_id: { type: "integer" },

    jugador_nombre: { type: ["string", "null"] },
    plan_nombre: { type: ["string", "null"] },
    tarifa_nombre: { type: ["string", "null"] },
    tipo_pago_nombre: { type: ["string", "null"] },
    sucursal_nombre: { type: ["string", "null"] },

    promocion_nombre: {
      type: ["string", "null"],
    },

    situacion_pago_nombre: {
      type: ["string", "null"],
    },

    created_at: { type: ["string", "null"] },
    updated_at: { type: ["string", "null"] },
  },

  required: [
    "id",
    "academia_id",
    "sucursal_id",
    "jugador_id",
    "jugador_plan_id",
    "tarifa_id",
    "tipo_pago_id",
    "periodo_desde",
    "periodo_hasta",
    "fecha_vencimiento",
    "monto_base",
    "monto_descuento",
    "monto_total",
    "situacion_pago_id",
  ],
} as const;

const CargoJugadorListResponse = {
  $id: "CargoJugadorListResponse",
  type: "object",

  properties: {
    ok: { type: "boolean" },
    count: { type: "integer" },

    items: {
      type: "array",
      items: { $ref: "CargoJugador#" },
    },
  },

  required: ["ok", "items"],
} as const;

/* =========================================================
   PAGOS JUGADOR
========================================================= */

const PagoJugador = {
  $id: "PagoJugador",
  type: "object",

  properties: {
    id: { type: "integer" },

    academia_id: { type: "integer" },

    /*
     * Pagos históricos pueden mantener NULL.
     */
    cargo_id: {
      type: ["integer", "null"],
    },

    jugador_rut: { type: "integer" },

    tipo_pago_id: { type: "integer" },
    situacion_pago_id: { type: "integer" },

    monto: { type: "number" },

    fecha_pago: {
      type: "string",
      format: "date",
    },

    medio_pago_id: { type: "integer" },

    comprobante_url: {
      type: ["string", "null"],
    },

    observaciones: {
      type: ["string", "null"],
    },
  },

  required: [
    "id",
    "academia_id",
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
    count: { type: "integer" },

    items: {
      type: "array",
      items: { $ref: "PagoJugador#" },
    },
  },

  required: ["ok", "items"],
} as const;

/* =========================================================
   ESTADÍSTICAS
========================================================= */

const Estadistica = {
  $id: "Estadistica",
  type: "object",

  additionalProperties: {
    type: ["integer", "number", "string", "boolean", "null"],
  },
} as const;

const EstadisticaResponse = {
  $id: "EstadisticaResponse",
  type: "object",

  properties: {
    ok: { type: "boolean" },

    items: {
      type: "array",
      items: { $ref: "Estadistica#" },
    },
  },

  required: ["ok", "items"],
} as const;

/* =========================================================
   NOTICIAS
========================================================= */

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

    items: {
      type: "array",
      items: { $ref: "EstadoNoticia#" },
    },
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

    is_popup: {
      type: ["integer", "boolean"],
    },

    popup_start_at: {
      type: ["string", "null"],
    },

    popup_end_at: {
      type: ["string", "null"],
    },

    pinned: {
      type: ["integer", "boolean"],
    },

    pinned_order: {
      type: ["integer", "string", "null"],
    },

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

    items: {
      type: "array",
      items: { $ref: "NoticiaListItem#" },
    },

    limit: { type: "integer" },
    offset: { type: "integer" },
    total: { type: "integer" },
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

    resumen: {
      type: ["string", "null"],
    },

    contenido: {
      type: ["string", "null"],
    },

    imagen_mime: {
      type: ["string", "null"],
    },

    imagen_base64: {
      type: ["string", "null"],
    },

    imagen_bytes: {
      type: ["integer", "string", "null"],
    },

    estado_noticia_id: {
      type: "integer",
    },

    estado_nombre: {
      type: "string",
    },

    published_at: {
      type: ["string", "null"],
    },

    is_popup: {
      type: ["integer", "boolean"],
    },

    popup_start_at: {
      type: ["string", "null"],
    },

    popup_end_at: {
      type: ["string", "null"],
    },

    pinned: {
      type: ["integer", "boolean"],
    },

    pinned_order: {
      type: ["integer", "string", "null"],
    },

    created_by_admin_id: {
      type: ["integer", "null"],
    },

    created_at: {
      type: "string",
    },

    updated_at: {
      type: "string",
    },
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

/* =========================================================
   REGISTRO CENTRAL DE SCHEMAS
========================================================= */

export async function registerSchemas(app: FastifyInstance) {
  /* ─────────────────────────────────────────────
     UTILIDADES / SEGURIDAD DOCUMENTAL
  ───────────────────────────────────────────── */

  app.addSchema(OkOnly);
  app.addSchema(ErrorResponse);
  app.addSchema(DeleteResponse);
  app.addSchema(HealthResponse);

  app.addSchema(UnauthorizedResponse);
  app.addSchema(ForbiddenResponse);

  /* ─────────────────────────────────────────────
     BASE CATÁLOGOS
  ───────────────────────────────────────────── */

  app.addSchema(CatalogoItem);
  app.addSchema(CatalogoTenantItem);

  app.addSchema(CatalogoListResponse);
  app.addSchema(CatalogoTenantListResponse);

  /* ─────────────────────────────────────────────
     CATÁLOGOS ESPECÍFICOS
  ───────────────────────────────────────────── */

  app.addSchema(Categoria);
  app.addSchema(CategoriaListResponse);

  app.addSchema(Comuna);
  app.addSchema(ComunaListResponse);

  app.addSchema(Deporte);
  app.addSchema(DeporteListResponse);

  app.addSchema(EstablecimientoEducacional);
  app.addSchema(EstablecimientoEducacionalListResponse);

  app.addSchema(Estado);
  app.addSchema(EstadoListResponse);

  app.addSchema(MedioPago);
  app.addSchema(MedioPagoListResponse);

  app.addSchema(Posicion);
  app.addSchema(PosicionListResponse);

  app.addSchema(PrevisionMedica);
  app.addSchema(PrevisionMedicaListResponse);

  app.addSchema(Rol);
  app.addSchema(RolListResponse);

  app.addSchema(SituacionPago);
  app.addSchema(SituacionPagoListResponse);

  app.addSchema(SucursalReal);
  app.addSchema(SucursalRealListResponse);

  app.addSchema(TipoPago);
  app.addSchema(TipoPagoListResponse);

  /* ─────────────────────────────────────────────
     USUARIOS / AUTENTICACIÓN
  ───────────────────────────────────────────── */

  app.addSchema(Usuario);
  app.addSchema(UsuarioListResponse);

  app.addSchema(AuthUser);
  app.addSchema(AuthResponse);

  app.addSchema(AuthApoderadoResponse);
  app.addSchema(PortalApoderado);

  /* ─────────────────────────────────────────────
     EVENTOS / CONVOCATORIAS
  ───────────────────────────────────────────── */

  app.addSchema(Evento);
  app.addSchema(EventoListResponse);

  app.addSchema(Convocatoria);
  app.addSchema(ConvocatoriaListResponse);

  app.addSchema(ConvocatoriaHistorico);
  app.addSchema(ConvocatoriaHistoricoListResponse);

  /* ─────────────────────────────────────────────
     ACADEMIAS
  ───────────────────────────────────────────── */

  app.addSchema(Academia);
  app.addSchema(AcademiaListResponse);

  /* ─────────────────────────────────────────────
     JUGADORES
  ───────────────────────────────────────────── */

  app.addSchema(Jugador);
  app.addSchema(JugadorListResponse);

  /* ─────────────────────────────────────────────
     PLANES
  ───────────────────────────────────────────── */

  app.addSchema(Plan);
  app.addSchema(PlanListResponse);

  app.addSchema(PlanSucursal);
  app.addSchema(PlanSucursalListResponse);

  /* ─────────────────────────────────────────────
     TARIFAS
  ───────────────────────────────────────────── */

  app.addSchema(PlanTarifa);
  app.addSchema(PlanTarifaListResponse);

  app.addSchema(TarifaSucursal);
  app.addSchema(TarifaSucursalListResponse);

  /* ─────────────────────────────────────────────
     PROMOCIONES
  ───────────────────────────────────────────── */

  app.addSchema(Promocion);
  app.addSchema(PromocionListResponse);

  app.addSchema(PromocionPlan);
  app.addSchema(PromocionPlanListResponse);

  app.addSchema(PromocionSucursal);
  app.addSchema(PromocionSucursalListResponse);

  app.addSchema(PromocionTipoPago);
  app.addSchema(PromocionTipoPagoListResponse);

  /* ─────────────────────────────────────────────
     JUGADOR ↔ PLAN
  ───────────────────────────────────────────── */

  app.addSchema(JugadorPlan);
  app.addSchema(JugadorPlanListResponse);

  /* ─────────────────────────────────────────────
     FINANZAS
  ───────────────────────────────────────────── */

  app.addSchema(CargoJugador);
  app.addSchema(CargoJugadorListResponse);

  app.addSchema(PagoJugador);
  app.addSchema(PagoJugadorListResponse);

  /* ─────────────────────────────────────────────
     ESTADÍSTICAS
  ───────────────────────────────────────────── */

  app.addSchema(Estadistica);
  app.addSchema(EstadisticaResponse);

  /* ─────────────────────────────────────────────
     NOTICIAS
  ───────────────────────────────────────────── */

  app.addSchema(EstadoNoticia);
  app.addSchema(EstadoNoticiaListResponse);

  app.addSchema(NoticiaListItem);
  app.addSchema(NoticiaListResponse);

  app.addSchema(NoticiaDetail);
  app.addSchema(NoticiaDetailResponse);
}
