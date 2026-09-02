// src/middlewares/authz.ts

import type { FastifyReply, FastifyRequest } from "fastify";
import jwt from "jsonwebtoken";
import { CONFIG } from "../config";
import { db } from "../db";

type AnyObj = Record<string, any>;

const PANEL_ROLES = new Set([1, 2, 3]);
const PANEL_TYPES = new Set(["admin", "user", "staff", "superadmin"]);
const JWT_ALGORITHM = "HS256" as const;

const JWT_ISSUER = String((CONFIG as any)?.JWT_ISSUER ?? process.env.JWT_ISSUER ?? "app").trim();

const JWT_AUDIENCE = String((CONFIG as any)?.JWT_AUDIENCE ?? process.env.JWT_AUDIENCE ?? "web").trim();

const ACADEMIA_ESTADO_ACTIVA = 1;
const ACADEMIA_ESTADO_DESACTIVADA = 2;

/* =========================================================
   AUTH CONTEXT
========================================================= */

export type AuthContext =
  | {
      type: "user";
      user_id: number;
      rol_id: number;
      academia_id: number | null;
    }
  | {
      type: "apoderado";
      rut: string;
      apoderado_id?: number;
      academia_id?: number;
    };

/* =========================================================
   JWT
========================================================= */

function getJwtSecret(): string {
  const secret = String(CONFIG.JWT_SECRET ?? process.env.JWT_SECRET ?? "");

  if (!secret) {
    throw new Error("JWT_SECRET missing");
  }

  if (secret.length < 32) {
    throw new Error("JWT_SECRET must contain at least 32 characters");
  }

  return secret;
}

/**
 * Compatibilidad temporal WELI:
 *
 * - decoded.user: estructura preferida actual.
 * - decoded.payload: compatibilidad con tokens anteriores.
 * - decoded: claims top-level.
 */
function extractUser(decoded: AnyObj): AnyObj {
  return decoded?.user ?? decoded?.payload ?? decoded ?? {};
}

/* =========================================================
   PARSERS
========================================================= */

function toPositiveInt(value: unknown): number | undefined {
  const n = Number(value);

  return Number.isSafeInteger(n) && n > 0 ? n : undefined;
}

function extractRole(user: AnyObj): number | undefined {
  const raw = user?.rol_id ?? user?.role_id ?? user?.roleId ?? user?.rolId ?? user?.rol ?? user?.role;

  const role = toPositiveInt(raw);

  return role && PANEL_ROLES.has(role) ? role : undefined;
}

function extractAcademiaId(user: AnyObj): number | undefined {
  const raw =
    user?.academia_id ?? user?.academy_id ?? user?.academiaId ?? user?.academyId ?? user?.academia ?? user?.academy;

  return toPositiveInt(raw);
}

/* =========================================================
   ESTADO ACADEMIA
========================================================= */

/**
 * Obtiene el estado real de la academia directamente desde BD.
 *
 * No confía en información almacenada dentro del JWT para el
 * estado porque una academia puede ser desactivada después de
 * que el token haya sido emitido.
 */
async function getAcademiaEstado(academiaId: number): Promise<number | null> {
  const [rows]: any = await db.query(
    `
        SELECT estado_id
        FROM academias
        WHERE id = ?
        LIMIT 1
      `,
    [academiaId]
  );

  if (!rows?.length) {
    return null;
  }

  const estadoId = Number(rows[0]?.estado_id);

  return Number.isInteger(estadoId) && estadoId > 0 ? estadoId : null;
}

/**
 * Comprueba que una academia tenant exista y se encuentre activa.
 *
 * Se utiliza para Admin/Staff.
 *
 * El Superadmin queda deliberadamente fuera de esta comprobación
 * porque debe poder administrar academias desactivadas.
 */
async function assertAcademiaActiva(academiaId: number): Promise<void> {
  const estadoId = await getAcademiaEstado(academiaId);

  if (estadoId === null) {
    throw Object.assign(new Error("ACADEMIA_NOT_FOUND"), {
      statusCode: 403,
      authzCode: "ACADEMIA_NOT_FOUND",
    });
  }

  if (estadoId !== ACADEMIA_ESTADO_ACTIVA) {
    throw Object.assign(new Error("ACADEMIA_DISABLED"), {
      statusCode: 403,
      authzCode: "ACADEMIA_DISABLED",
      academiaEstadoId: estadoId,
    });
  }
}

/* =========================================================
   RESPUESTAS DE ESTADO ACADEMIA
========================================================= */

function sendAcademiaAccessError(
  req: FastifyRequest,
  reply: FastifyReply,
  error: any,
  context?: {
    user_id?: number;
    rol_id?: number;
    academia_id?: number;
  }
) {
  const code = String(error?.authzCode ?? error?.message ?? "");

  if (code === "ACADEMIA_DISABLED") {
    req.log.warn(
      {
        ...context,

        estado_id: error?.academiaEstadoId,
      },
      "[authz] acceso bloqueado por academia desactivada"
    );

    return reply.code(403).send({
      ok: false,
      message: "ACADEMIA_DISABLED",

      academia_estado_id: Number(error?.academiaEstadoId ?? ACADEMIA_ESTADO_DESACTIVADA),
    });
  }

  if (code === "ACADEMIA_NOT_FOUND") {
    req.log.warn(context ?? {}, "[authz] academia asociada no existe");

    return reply.code(403).send({
      ok: false,
      message: "ACADEMIA_NOT_FOUND",
    });
  }

  /*
   * Este punto es importante:
   *
   * Un error inesperado consultando la academia no significa
   * que el JWT sea inválido.
   *
   * Ejemplos:
   * - MySQL caído;
   * - timeout;
   * - pool agotado;
   * - error de infraestructura.
   *
   * No devolvemos 401 porque el frontend interpretaría que
   * debe destruir una sesión perfectamente válida.
   */
  req.log.error(
    {
      ...context,
      message: error?.message,
      code: error?.code,
    },
    "[authz] error verificando estado de academia"
  );

  return reply.code(503).send({
    ok: false,
    message: "AUTH_SERVICE_UNAVAILABLE",
  });
}

/* =========================================================
   COMPATIBILIDAD REQ.USER
========================================================= */

/**
 * Compatibilidad temporal para routers/hooks antiguos que
 * todavía hayan creado req.user antes de req.auth.
 */
function readLegacyAuthFromReq(req: FastifyRequest): AuthContext | undefined {
  const user = (req as any).user as AnyObj | undefined;

  if (!user) {
    return undefined;
  }

  const type = String(user?.type ?? "")
    .trim()
    .toLowerCase();

  /* Apoderado */

  if (type === "apoderado") {
    const rut = String(user?.rut ?? "").trim();

    if (!/^\d{8}$/.test(rut)) {
      return undefined;
    }

    const apoderado_id = toPositiveInt(user?.apoderado_id);

    const academia_id = extractAcademiaId(user);

    return {
      type: "apoderado",

      rut,

      ...(apoderado_id
        ? {
            apoderado_id,
          }
        : {}),

      ...(academia_id
        ? {
            academia_id,
          }
        : {}),
    };
  }

  /* Panel */

  if (!PANEL_TYPES.has(type)) {
    return undefined;
  }

  const rol_id = extractRole(user);

  const user_id = toPositiveInt(user?.user_id ?? user?.id ?? user?.uid);

  if (!rol_id || !user_id) {
    return undefined;
  }

  if (rol_id === 3) {
    return {
      type: "user",
      user_id,
      rol_id,
      academia_id: null,
    };
  }

  const academia_id = extractAcademiaId(user);

  if (!academia_id) {
    return undefined;
  }

  return {
    type: "user",
    user_id,
    rol_id,
    academia_id,
  };
}

/**
 * Single source of truth durante la request:
 *
 * req.auth
 */
function ensureAuthContext(req: FastifyRequest): AuthContext | undefined {
  const current = (req as any).auth as AuthContext | undefined;

  if (current) {
    return current;
  }

  /*
   * Compatibilidad temporal.
   *
   * Debe desaparecer progresivamente cuando todos los routers
   * dependan exclusivamente de requireAuth -> req.auth.
   */
  const recovered = readLegacyAuthFromReq(req);

  if (recovered) {
    (req as any).auth = recovered;

    return recovered;
  }

  return undefined;
}

/* =========================================================
   REQUIRE AUTH
========================================================= */

/**
 * Requiere Bearer JWT válido.
 *
 * Valida:
 *
 * - firma;
 * - algoritmo;
 * - issuer;
 * - audience;
 * - expiración;
 * - estructura;
 * - rol;
 * - academia para Admin/Staff;
 * - estado actual de la academia para Admin/Staff.
 *
 * IMPORTANTE:
 *
 * Una academia desactivada invalida operativamente las sesiones
 * de Admin y Staff aunque el JWT todavía no haya expirado.
 */
export async function requireAuth(req: FastifyRequest, reply: FastifyReply) {
  const authorization = String(req.headers.authorization ?? "").trim();

  const match = authorization.match(/^Bearer\s+(\S+)$/i);

  if (!match) {
    return reply.code(401).send({
      ok: false,
      message: "UNAUTHORIZED",
    });
  }

  const token = match[1];

  /* =======================================================
     CONFIGURACIÓN JWT
  ======================================================= */

  let jwtSecret: string;

  try {
    jwtSecret = getJwtSecret();
  } catch (error: any) {
    /*
     * Un JWT_SECRET inexistente o inválido es un problema del
     * servidor, no del usuario ni de su token.
     */
    req.log.error(
      {
        message: error?.message,
      },
      "[authz] invalid JWT configuration"
    );

    return reply.code(500).send({
      ok: false,
      message: "AUTH_CONFIGURATION_ERROR",
    });
  }

  /* =======================================================
     VERIFICACIÓN CRIPTOGRÁFICA JWT
  ======================================================= */

  let decoded: AnyObj;

  try {
    decoded = jwt.verify(token, jwtSecret, {
      algorithms: [JWT_ALGORITHM],

      issuer: JWT_ISSUER,

      audience: JWT_AUDIENCE,
    }) as AnyObj;
  } catch (error: any) {
    /*
     * Solo errores propios de la verificación JWT llegan aquí.
     *
     * Firma inválida, token expirado, issuer incorrecto,
     * audience incorrecto, algoritmo no permitido, etc.
     */
    req.log.warn(
      {
        message: error?.message,
      },
      "[authz] invalid authentication token"
    );

    return reply.code(401).send({
      ok: false,
      message: "INVALID_TOKEN",
    });
  }

  const user = extractUser(decoded);

  const type = String(user?.type ?? "")
    .trim()
    .toLowerCase();

  /* =======================================================
     APODERADO
     Se conserva la lógica existente.
     Su revisión integral queda fuera de esta etapa.
  ======================================================= */

  if (type === "apoderado") {
    const rut = String(user?.rut ?? "").trim();

    if (!/^\d{8}$/.test(rut)) {
      return reply.code(401).send({
        ok: false,
        message: "INVALID_TOKEN",
      });
    }

    const apoderado_id = toPositiveInt(user?.apoderado_id);

    /*
     * Compatibilidad actual:
     *
     * Si el JWT del Apoderado incorpora academia_id,
     * se comprueba su estado.
     *
     * Si no lo incorpora, NO se inventa una academia.
     *
     * La revisión integral del modelo Apoderado se realizará
     * posteriormente y de forma separada.
     */
    const academia_id = extractAcademiaId(user);

    if (academia_id) {
      try {
        await assertAcademiaActiva(academia_id);
      } catch (error: any) {
        return sendAcademiaAccessError(req, reply, error, {
          academia_id,
        });
      }
    }

    const authContext: AuthContext = {
      type: "apoderado",

      rut,

      ...(apoderado_id
        ? {
            apoderado_id,
          }
        : {}),

      ...(academia_id
        ? {
            academia_id,
          }
        : {}),
    };

    (req as any).auth = authContext;

    /*
     * Compatibilidad temporal.
     */
    (req as any).user = user;

    return;
  }

  /* =======================================================
     PANEL
  ======================================================= */

  if (!PANEL_TYPES.has(type)) {
    return reply.code(401).send({
      ok: false,
      message: "INVALID_TOKEN",
    });
  }

  const rol_id = extractRole(user);

  const user_id = toPositiveInt(user?.user_id ?? user?.id ?? user?.uid);

  if (!rol_id || !user_id) {
    return reply.code(401).send({
      ok: false,
      message: "INVALID_TOKEN",
    });
  }

  let academia_id: number | null = null;

  /* =======================================================
     SUPERADMIN
  ======================================================= */

  if (rol_id === 3) {
    /*
     * Superadmin NO queda ligado a una academia dentro del JWT.
     *
     * Tampoco validamos el estado de una academia aquí porque
     * requireAuth autentica al usuario, no determina todavía
     * qué tenant administrará.
     *
     * El tenant objetivo será resuelto posteriormente por:
     *
     * getEffectiveAcademiaId(req)
     *
     * usando x-academia-id.
     *
     * Esto permite al Superadmin:
     *
     * - visualizar academias desactivadas;
     * - editarlas;
     * - reactivarlas;
     * - eliminarlas.
     */
    academia_id = null;
  } else {
    /* =====================================================
       ADMIN / STAFF
    ===================================================== */

    const academiaToken = extractAcademiaId(user);

    if (!academiaToken) {
      /*
       * Admin/Staff sin academia firmada constituye un token
       * estructuralmente inválido.
       */
      return reply.code(401).send({
        ok: false,
        message: "INVALID_TOKEN",
      });
    }

    academia_id = academiaToken;

    /*
     * CRÍTICO:
     *
     * El estado se consulta directamente desde BD en cada
     * request.
     *
     * Por eso, si Superadmin desactiva la academia, un JWT
     * previamente emitido queda bloqueado inmediatamente.
     */
    try {
      await assertAcademiaActiva(academiaToken);
    } catch (error: any) {
      return sendAcademiaAccessError(req, reply, error, {
        user_id,
        rol_id,
        academia_id: academiaToken,
      });
    }
  }

  const authContext: AuthContext = {
    type: "user",

    user_id,
    rol_id,
    academia_id,
  };

  /*
   * req.auth es la fuente canónica para autorización durante
   * la request.
   */
  (req as any).auth = authContext;

  /*
   * Compatibilidad temporal con routers antiguos.
   *
   * Mantiene el contenido verificado del JWT.
   */
  (req as any).user = user;

  (req as any).role_id = rol_id;

  return;
}

/* =========================================================
   APODERADO
========================================================= */

export async function requireApoderado(req: FastifyRequest, reply: FastifyReply) {
  const auth = ensureAuthContext(req);

  if (!auth || auth.type !== "apoderado") {
    return reply.code(403).send({
      ok: false,
      message: "FORBIDDEN",
    });
  }
}

/* =========================================================
   ROLES PANEL
========================================================= */

export function requireRoles(allowed: number[]) {
  const allowedRoles = new Set(allowed.map(Number).filter((role) => Number.isInteger(role) && PANEL_ROLES.has(role)));

  return async function (req: FastifyRequest, reply: FastifyReply) {
    const auth = ensureAuthContext(req);

    if (!auth || auth.type !== "user") {
      return reply.code(403).send({
        ok: false,
        message: "FORBIDDEN",
      });
    }

    const role = auth.rol_id;

    if (!allowedRoles.has(role)) {
      req.log.warn(
        {
          role,

          allowed: [...allowedRoles],
        },
        "[authz] forbidden by role"
      );

      return reply.code(403).send({
        ok: false,
        message: "FORBIDDEN",
      });
    }
  };
}

/* =========================================================
   MULTI-TENANT HELPERS
========================================================= */

/**
 * Regla WELI:
 *
 * rol 3:
 *   academia objetivo = x-academia-id obligatorio.
 *
 * rol 1 / 2:
 *   academia = JWT firmado.
 *   si existe x-academia-id, debe coincidir exactamente.
 */

export function getRolId(req: FastifyRequest): number {
  const auth = ensureAuthContext(req);

  if (!auth || auth.type !== "user") {
    return 0;
  }

  const role = Number(auth.rol_id);

  return Number.isInteger(role) && PANEL_ROLES.has(role) ? role : 0;
}

export function getTokenAcademiaId(req: FastifyRequest): number {
  const auth = ensureAuthContext(req);

  if (!auth || auth.type !== "user") {
    return 0;
  }

  /*
   * Superadmin no tiene tenant ligado en el JWT.
   */
  if (auth.rol_id === 3) {
    return 0;
  }

  const academiaId = Number(auth.academia_id);

  return Number.isSafeInteger(academiaId) && academiaId > 0 ? academiaId : 0;
}

/**
 * Lee x-academia-id de forma estricta.
 *
 * Solo acepta enteros decimales positivos:
 *
 * 1
 * 25
 * 300
 *
 * Rechaza:
 *
 * 1e2
 * 2.5
 * -1
 * +10
 * Infinity
 * NaN
 * cadenas arbitrarias
 */
export function getHeaderAcademiaId(req: FastifyRequest): number {
  const header = req.headers["x-academia-id"];

  const raw = Array.isArray(header) ? header[0] : header;

  const value = String(raw ?? "").trim();

  if (!/^\d+$/.test(value)) {
    return 0;
  }

  const academiaId = Number(value);

  return Number.isSafeInteger(academiaId) && academiaId > 0 ? academiaId : 0;
}

/**
 * Tenant definitivo WELI.
 */
export function getEffectiveAcademiaId(req: FastifyRequest): number {
  const rol = getRolId(req);

  if (!PANEL_ROLES.has(rol)) {
    throw Object.assign(new Error("FORBIDDEN: rol inválido"), {
      statusCode: 403,
    });
  }

  const headerAcademia = getHeaderAcademiaId(req);

  const tokenAcademia = getTokenAcademiaId(req);

  /* =======================================================
     SUPERADMIN
  ======================================================= */

  if (rol === 3) {
    /*
     * Para acceder a información tenantizada el Superadmin
     * DEBE indicar explícitamente la academia objetivo.
     */
    if (!headerAcademia) {
      throw Object.assign(new Error("FORBIDDEN: falta x-academia-id para superadmin"), {
        statusCode: 403,
      });
    }

    return headerAcademia;
  }

  /* =======================================================
     ADMIN / STAFF
  ======================================================= */

  /*
   * Para Admin/Staff la fuente de verdad siempre es el JWT
   * firmado.
   */
  if (!tokenAcademia) {
    throw Object.assign(new Error("FORBIDDEN: token sin academia_id"), {
      statusCode: 403,
    });
  }

  /*
   * El header es opcional para Admin/Staff.
   *
   * Si api.js lo envía, tiene que coincidir EXACTAMENTE con
   * la academia firmada en el JWT.
   *
   * Esto evita:
   *
   * Admin academia 4
   *       +
   * x-academia-id: 7
   *       ↓
   * 403
   */
  if (headerAcademia) {
    if (headerAcademia !== tokenAcademia) {
      throw Object.assign(new Error("FORBIDDEN: x-academia-id no coincide con tu academia"), {
        statusCode: 403,
      });
    }

    return headerAcademia;
  }

  return tokenAcademia;
}
