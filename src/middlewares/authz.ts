// src/middlewares/authz.ts

import type { FastifyReply, FastifyRequest } from "fastify";
import jwt from "jsonwebtoken";
import { CONFIG } from "../config";

type AnyObj = Record<string, any>;

const PANEL_ROLES = new Set([1, 2, 3]);
const PANEL_TYPES = new Set(["admin", "user", "staff", "superadmin"]);
const JWT_ALGORITHM = "HS256" as const;

const JWT_ISSUER = String((CONFIG as any)?.JWT_ISSUER ?? process.env.JWT_ISSUER ?? "app").trim();
const JWT_AUDIENCE = String((CONFIG as any)?.JWT_AUDIENCE ?? process.env.JWT_AUDIENCE ?? "web").trim();

/* ───────────────────────── Auth context ───────────────────────── */

export type AuthContext =
  | { type: "user"; user_id: number; rol_id: number; academia_id: number | null }
  | { type: "apoderado"; rut: string; apoderado_id?: number };

/* ───────────────────────── JWT ───────────────────────── */

function getJwtSecret() {
  const secret = String(CONFIG.JWT_SECRET ?? process.env.JWT_SECRET ?? "");

  if (!secret) throw new Error("JWT_SECRET missing");
  if (secret.length < 32) throw new Error("JWT_SECRET must contain at least 32 characters");

  return secret;
}

/**
 * Compatibilidad temporal WELI:
 * - decoded.user: estructura preferida actual.
 * - decoded.payload: compatibilidad con tokens anteriores.
 * - decoded: claims top-level.
 *
 * Cuando terminemos la purga global podremos reducir esto.
 */
function extractUser(decoded: AnyObj): AnyObj {
  return decoded?.user ?? decoded?.payload ?? decoded ?? {};
}

/* ───────────────────────── Parsers seguros ───────────────────────── */

function toPositiveInt(value: unknown): number | undefined {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : undefined;
}

function extractRole(user: AnyObj): number | undefined {
  const raw =
    user?.rol_id ??
    user?.role_id ??
    user?.roleId ??
    user?.rolId ??
    user?.rol ??
    user?.role;

  const role = toPositiveInt(raw);
  return role && PANEL_ROLES.has(role) ? role : undefined;
}

function extractAcademiaId(user: AnyObj): number | undefined {
  const raw =
    user?.academia_id ??
    user?.academy_id ??
    user?.academiaId ??
    user?.academyId ??
    user?.academia ??
    user?.academy;

  return toPositiveInt(raw);
}

/* ───────────────────────── Compatibilidad req.user ───────────────────────── */

/**
 * Compatibilidad temporal para routers/hooks antiguos que todavía hayan
 * creado req.user antes de req.auth.
 *
 * No acepta tipos, roles ni IDs arbitrarios.
 */
function readLegacyAuthFromReq(req: FastifyRequest): AuthContext | undefined {
  const user = (req as any).user as AnyObj | undefined;
  if (!user) return undefined;

  const type = String(user?.type ?? "").trim().toLowerCase();

  /* Portal apoderado */
  if (type === "apoderado") {
    const rut = String(user?.rut ?? "").trim();
    if (!/^\d{8}$/.test(rut)) return undefined;

    const apoderado_id = toPositiveInt(user?.apoderado_id);

    return {
      type: "apoderado",
      rut,
      ...(apoderado_id ? { apoderado_id } : {}),
    };
  }

  /* Panel */
  if (!PANEL_TYPES.has(type)) return undefined;

  const rol_id = extractRole(user);
  const user_id = toPositiveInt(user?.user_id ?? user?.id ?? user?.uid);

  if (!rol_id || !user_id) return undefined;

  if (rol_id === 3) {
    return {
      type: "user",
      user_id,
      rol_id,
      academia_id: null,
    };
  }

  const academia_id = extractAcademiaId(user);
  if (!academia_id) return undefined;

  return {
    type: "user",
    user_id,
    rol_id,
    academia_id,
  };
}

/**
 * Single source of truth durante la request:
 * req.auth.
 *
 * El fallback desde req.user se conserva temporalmente
 * mientras terminamos la purga global.
 */
function ensureAuthContext(req: FastifyRequest): AuthContext | undefined {
  const current = (req as any).auth as AuthContext | undefined;
  if (current) return current;

  const recovered = readLegacyAuthFromReq(req);

  if (recovered) {
    (req as any).auth = recovered;
    return recovered;
  }

  return undefined;
}

/* ───────────────────────── requireAuth ───────────────────────── */

/**
 * Requiere Bearer JWT válido.
 *
 * Valida:
 * - firma
 * - algoritmo
 * - issuer
 * - audience
 * - expiración
 * - estructura de identidad
 * - rol
 * - academia para Admin/Staff
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

  try {
    const decoded = jwt.verify(token, getJwtSecret(), {
      algorithms: [JWT_ALGORITHM],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    }) as AnyObj;

    const user = extractUser(decoded);
    const type = String(user?.type ?? "").trim().toLowerCase();

    /* ───────── Apoderado ───────── */

    if (type === "apoderado") {
      const rut = String(user?.rut ?? "").trim();

      if (!/^\d{8}$/.test(rut)) {
        return reply.code(401).send({
          ok: false,
          message: "INVALID_TOKEN",
        });
      }

      const apoderado_id = toPositiveInt(user?.apoderado_id);

      const authContext: AuthContext = {
        type: "apoderado",
        rut,
        ...(apoderado_id ? { apoderado_id } : {}),
      };

      (req as any).auth = authContext;

      /*
       * Compatibilidad temporal.
       * Se retirará cuando la purga determine que ningún router
       * depende ya de req.user.
       */
      (req as any).user = user;

      return;
    }

    /* ───────── Panel ───────── */

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

    if (rol_id === 3) {
      /*
       * Superadmin:
       * no queda ligado a una academia dentro del JWT.
       * El tenant objetivo se determina por x-academia-id.
       */
      academia_id = null;
    } else {
      /*
       * Admin / Staff:
       * academia obligatoria desde token firmado.
       */
      const academiaToken = extractAcademiaId(user);

      if (!academiaToken) {
        return reply.code(401).send({
          ok: false,
          message: "INVALID_TOKEN",
        });
      }

      academia_id = academiaToken;
    }

    const authContext: AuthContext = {
      type: "user",
      user_id,
      rol_id,
      academia_id,
    };

    (req as any).auth = authContext;

    /*
     * Compatibilidad temporal.
     */
    (req as any).user = user;
    (req as any).role_id = rol_id;

    return;
  } catch {
    return reply.code(401).send({
      ok: false,
      message: "INVALID_TOKEN",
    });
  }
}

/* ───────────────────────── Apoderado ───────────────────────── */

export async function requireApoderado(req: FastifyRequest, reply: FastifyReply) {
  const auth = ensureAuthContext(req);

  if (!auth || auth.type !== "apoderado") {
    return reply.code(403).send({
      ok: false,
      message: "FORBIDDEN",
    });
  }
}

/* ───────────────────────── Roles panel ───────────────────────── */

export function requireRoles(allowed: number[]) {
  const allowedRoles = new Set(
    allowed
      .map(Number)
      .filter((role) => Number.isInteger(role) && PANEL_ROLES.has(role))
  );

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

/* ───────────────────────── Multi-tenant helpers ───────────────────────── */

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

  if (!auth || auth.type !== "user") return 0;

  const role = Number(auth.rol_id);

  return Number.isInteger(role) && PANEL_ROLES.has(role) ? role : 0;
}

export function getTokenAcademiaId(req: FastifyRequest): number {
  const auth = ensureAuthContext(req);

  if (!auth || auth.type !== "user") return 0;

  /*
   * Superadmin tiene academia_id null.
   */
  if (auth.rol_id === 3) return 0;

  const academiaId = Number(auth.academia_id);

  return Number.isInteger(academiaId) && academiaId > 0 ? academiaId : 0;
}

export function getHeaderAcademiaId(req: FastifyRequest): number {
  const header = req.headers["x-academia-id"];
  const raw = Array.isArray(header) ? header[0] : header;

  /*
   * No aceptamos:
   * 2.5
   * -1
   * NaN
   * Infinity
   * cadenas arbitrarias
   */
  const academiaId = Number(raw);

  return Number.isInteger(academiaId) && academiaId > 0 ? academiaId : 0;
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

  /* ───────── Superadmin ───────── */

  if (rol === 3) {
    if (!headerAcademia) {
      throw Object.assign(
        new Error("FORBIDDEN: falta x-academia-id para superadmin"),
        { statusCode: 403 }
      );
    }

    return headerAcademia;
  }

  /* ───────── Admin / Staff ───────── */

  if (!tokenAcademia) {
    throw Object.assign(new Error("FORBIDDEN: token sin academia_id"), {
      statusCode: 403,
    });
  }

  /*
   * Header opcional.
   *
   * Si existe, debe coincidir exactamente con el JWT.
   */
  if (headerAcademia) {
    if (headerAcademia !== tokenAcademia) {
      throw Object.assign(
        new Error("FORBIDDEN: x-academia-id no coincide con tu academia"),
        { statusCode: 403 }
      );
    }

    return headerAcademia;
  }

  return tokenAcademia;
}