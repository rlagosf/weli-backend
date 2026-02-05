// src/middlewares/authz.ts
import type { FastifyReply, FastifyRequest } from "fastify";
import jwt from "jsonwebtoken";
import { CONFIG } from "../config";

type AnyObj = Record<string, any>;

type AuthContext =
  | { type: "user"; user_id?: number; rol_id?: number; academia_id?: number }
  | { type: "apoderado"; rut: string; apoderado_id?: number };

function getJwtSecret() {
  const s = CONFIG.JWT_SECRET;
  if (!s) throw new Error("JWT_SECRET missing (CONFIG.JWT_SECRET)");
  return s;
}

function extractUser(decoded: AnyObj): AnyObj {
  // soporta tokens donde vienen anidados
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

export async function requireAuth(req: FastifyRequest, reply: FastifyReply) {
  const auth = String(req.headers.authorization || "");
  const [bearer, token] = auth.split(" ");

  if (bearer !== "Bearer" || !token) {
    return reply.code(401).send({ ok: false, message: "UNAUTHORIZED" });
  }

  try {
    const decoded = jwt.verify(token, getJwtSecret()) as AnyObj;
    const user = extractUser(decoded);

    // --- Caso APODERADO (token: { type:"apoderado", rut, apoderado_id? }) ---
    const type = String(user?.type ?? "").toLowerCase();
    if (type === "apoderado") {
      const rut = String(user?.rut ?? "");
      if (!/^\d{8}$/.test(rut)) {
        return reply.code(401).send({ ok: false, message: "INVALID_TOKEN" });
      }

      const apoderado_id = toInt(user?.apoderado_id);
      (req as any).auth = { type: "apoderado", rut, apoderado_id } satisfies AuthContext;

      // compat legacy
      (req as any).user = user;

      return;
    }

    // --- Caso ADMIN/STAFF (token con rol_id, user_id, academia_id, etc) ---
    const rol_id = extractRole(user);
    const user_id = toInt(user?.user_id ?? user?.id ?? user?.uid);
    const academia_id = extractAcademiaId(user);

    (req as any).auth = { type: "user", user_id, rol_id, academia_id } satisfies AuthContext;

    // compat legacy
    (req as any).user = user;
    (req as any).role_id = rol_id ?? null;

    return;
  } catch {
    return reply.code(401).send({ ok: false, message: "INVALID_TOKEN" });
  }
}

export async function requireApoderado(req: FastifyRequest, reply: FastifyReply) {
  const a = (req as any).auth as AuthContext | undefined;
  if (!a || a.type !== "apoderado") {
    return reply.code(403).send({ ok: false, message: "FORBIDDEN" });
  }
}

export function requireRoles(allowed: number[]) {
  const set = new Set(allowed.map(Number));

  return async function (req: FastifyRequest, reply: FastifyReply) {
    const a = (req as any).auth as AuthContext | undefined;

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
