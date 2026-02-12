// src/middlewares/authz.ts
import type { FastifyReply, FastifyRequest } from "fastify";
import jwt from "jsonwebtoken";
import { CONFIG } from "../config";

type AnyObj = Record<string, any>;

/**
 * AuthContext normalizado (single source of truth):
 * - user: panel (admin/staff/superadmin)
 * - apoderado: portal apoderado
 */
export type AuthContext =
  | { type: "user"; user_id?: number; rol_id?: number; academia_id?: number | null }
  | { type: "apoderado"; rut: string; apoderado_id?: number };

function getJwtSecret() {
  const s = CONFIG.JWT_SECRET ?? (process.env.JWT_SECRET as any);
  if (!s) throw new Error("JWT_SECRET missing (CONFIG.JWT_SECRET)");
  return String(s);
}

/**
 * Soporta tokens con payload en:
 * - decoded.user (preferido)
 * - decoded.payload
 * - decoded (top-level legacy)
 */
function extractUser(decoded: AnyObj): AnyObj {
  return decoded?.user ?? decoded?.payload ?? decoded ?? {};
}

function toInt(v: any): number | undefined {
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

function extractRole(user: AnyObj): number | undefined {
  const raw =
    user?.rol_id ??
    user?.role_id ??
    user?.roleId ??
    user?.rolId ??
    user?.rol ??
    user?.role ??
    undefined;

  return toInt(raw);
}

function extractAcademiaId(user: AnyObj): number | undefined {
  const raw =
    user?.academia_id ??
    user?.academy_id ??
    user?.academiaId ??
    user?.academyId ??
    user?.academia ??
    user?.academy ??
    undefined;

  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

/**
 * ✅ Fallback duro: si el backend ya armó req.user en un hook global
 * reconstruimos req.auth para que requireRoles / tenant helpers funcionen.
 */
function readLegacyAuthFromReq(req: FastifyRequest): AuthContext | undefined {
  const u = (req as any).user as AnyObj | undefined;
  if (!u) return undefined;

  const type = String(u?.type ?? "").toLowerCase();

  // Panel
  if (type === "admin" || type === "user" || type === "staff" || type === "superadmin") {
    const rol_id = extractRole(u);
    const user_id = toInt(u?.user_id ?? u?.id ?? u?.uid);
    const academia_id = extractAcademiaId(u) ?? (toInt(u?.academia_id) ?? undefined);

    return { type: "user", user_id, rol_id, academia_id };
  }

  // Apoderado
  if (type === "apoderado") {
    const rut = String(u?.rut ?? "");
    if (!/^\d{8}$/.test(rut)) return undefined;
    const apoderado_id = toInt(u?.apoderado_id);
    return { type: "apoderado", rut, apoderado_id };
  }

  return undefined;
}

/** ✅ Normaliza: si no existe req.auth, intenta reconstruirlo desde req.user */
function ensureAuthContext(req: FastifyRequest): AuthContext | undefined {
  let a = (req as any).auth as AuthContext | undefined;

  if (!a) {
    a = readLegacyAuthFromReq(req);
    if (a) (req as any).auth = a;
  }

  return a;
}

/**
 * ✅ Middleware: requiere Bearer token válido.
 * - setea req.auth y mantiene req.user por compatibilidad
 */
export async function requireAuth(req: FastifyRequest, reply: FastifyReply) {
  const auth = String(req.headers.authorization || "");
  const [bearer, token] = auth.split(" ");

  if (bearer !== "Bearer" || !token) {
    return reply.code(401).send({ ok: false, message: "UNAUTHORIZED" });
  }

  try {
    const decoded = jwt.verify(token, getJwtSecret()) as AnyObj;
    const user = extractUser(decoded);

    const type = String(user?.type ?? "").toLowerCase();

    // --- APODERADO ---
    if (type === "apoderado") {
      const rut = String(user?.rut ?? "");
      if (!/^\d{8}$/.test(rut)) {
        return reply.code(401).send({ ok: false, message: "INVALID_TOKEN" });
      }

      const apoderado_id = toInt(user?.apoderado_id);

      (req as any).auth = { type: "apoderado", rut, apoderado_id } satisfies AuthContext;
      (req as any).user = user; // legacy
      return;
    }

    // --- PANEL (admin/staff/superadmin) ---
    const rol_id = extractRole(user);
    const user_id = toInt(user?.user_id ?? user?.id ?? user?.uid);

    // superadmin puede venir con academia_id null
    const academia_id = extractAcademiaId(user);
    const academia_id_effective: number | null | undefined =
      rol_id === 3 ? null : academia_id;

    (req as any).auth = {
      type: "user",
      user_id,
      rol_id,
      academia_id: academia_id_effective,
    } satisfies AuthContext;

    // compat legacy
    (req as any).user = user;
    (req as any).role_id = rol_id ?? null;

    return;
  } catch {
    return reply.code(401).send({ ok: false, message: "INVALID_TOKEN" });
  }
}

export async function requireApoderado(req: FastifyRequest, reply: FastifyReply) {
  const a = ensureAuthContext(req);
  if (!a || a.type !== "apoderado") {
    return reply.code(403).send({ ok: false, message: "FORBIDDEN" });
  }
}

export function requireRoles(allowed: number[]) {
  const set = new Set(allowed.map(Number));

  return async function (req: FastifyRequest, reply: FastifyReply) {
    const a = ensureAuthContext(req);

    if (!a || a.type !== "user") {
      return reply.code(403).send({ ok: false, message: "FORBIDDEN" });
    }

    const role = Number(a.rol_id ?? 0);
    if (!set.has(role)) {
      req.log.warn({ role, allowed }, "[authz] forbidden by role");
      return reply.code(403).send({ ok: false, message: "FORBIDDEN" });
    }
  };
}

/* ──────────────────────────────────────────────────────────────
   ✅ Multi-tenant helpers (OPCIÓN 2) — exportables
   Regla:
   - rol 3 (superadmin): x-academia-id OBLIGATORIO
   - rol 1/2 (admin/staff): academia_id desde token
     - si viene x-academia-id, debe coincidir con token
────────────────────────────────────────────────────────────── */

export function getRolId(req: FastifyRequest): number {
  const a = ensureAuthContext(req) as any;
  const u: any = (req as any).user;

  const raw =
    (a?.type === "user" ? a?.rol_id : undefined) ??
    u?.rol_id ??
    u?.role_id ??
    u?.roleId ??
    u?.rolId ??
    u?.rol ??
    u?.role ??
    0;

  const n = Number(raw);
  return Number.isFinite(n) ? n : 0;
}

export function getTokenAcademiaId(req: FastifyRequest): number {
  const a = ensureAuthContext(req) as any;
  const u: any = (req as any).user;

  const raw =
    (a?.type === "user" ? a?.academia_id : undefined) ??
    u?.academia_id ??
    u?.academy_id ??
    u?.academiaId ??
    u?.academyId ??
    u?.academia ??
    u?.academy ??
    0;

  const n = Number(raw);
  return Number.isFinite(n) ? n : 0;
}

export function getHeaderAcademiaId(req: FastifyRequest): number {
  const hdr = req.headers["x-academia-id"];
  const raw = Array.isArray(hdr) ? hdr[0] : hdr;
  const n = Number(raw);
  return Number.isFinite(n) ? n : 0;
}

/**
 * ✅ Tenant definitivo:
 * - Superadmin: requiere header (si no, 403)
 * - Admin/Staff: header opcional, pero si viene debe coincidir con token
 * - Si no viene header: usa token
 */
export function getEffectiveAcademiaId(req: FastifyRequest): number {
  const rol = getRolId(req);
  const headerAcademia = getHeaderAcademiaId(req);
  const tokenAcademia = getTokenAcademiaId(req);

  // Superadmin: header manda (obligatorio)
  if (rol === 3) {
    if (!headerAcademia || headerAcademia <= 0) {
      throw Object.assign(new Error("FORBIDDEN: falta x-academia-id para superadmin"), {
        statusCode: 403,
      });
    }
    return headerAcademia;
  }

  // Admin/Staff: si viene header, debe coincidir con token
  if (headerAcademia && headerAcademia > 0) {
    if (!tokenAcademia || tokenAcademia <= 0) {
      throw Object.assign(new Error("FORBIDDEN: token sin academia_id"), { statusCode: 403 });
    }
    if (headerAcademia !== tokenAcademia) {
      throw Object.assign(new Error("FORBIDDEN: x-academia-id no coincide con tu academia"), {
        statusCode: 403,
      });
    }
    return headerAcademia;
  }

  // Fallback: token
  if (!tokenAcademia || tokenAcademia <= 0) {
    throw Object.assign(new Error("FORBIDDEN: token sin academia_id"), { statusCode: 403 });
  }
  return tokenAcademia;
}
