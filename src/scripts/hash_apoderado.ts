// src/scripts/hash_apoderado.ts
import * as argon2 from "@node-rs/argon2";
import { getDb } from "../db";

type EnsureResult =
  | { ok: true; created: boolean; rut_apoderado: string }
  | { ok: false; created: false; message: string };

function normalizeRut8(rutLike: string) {
  const rutNum = String(rutLike ?? "").trim().replace(/[^\d]/g, "");
  return rutNum;
}

/**
 * Crea credencial en apoderados_auth si NO existe.
 * - No pisa password si ya existe (modo seguro).
 * - must_change_password = 1 para forzar cambio en el primer login.
 *
 * Nota: Por defecto toma APODERADO_PROVISIONAL_PASSWORD del .env (o fallback RAFC2025!).
 */
export async function ensureApoderadoAuth({
  rut_apoderado,
  provisionalPlainPassword = process.env.APODERADO_PROVISIONAL_PASSWORD || "RAFC2025!",
}: {
  rut_apoderado: string;
  provisionalPlainPassword?: string;
}): Promise<EnsureResult> {
  const rut8 = normalizeRut8(rut_apoderado);

  // Tu sistema usa 8 dígitos sin DV
  if (!/^\d{8}$/.test(rut8)) {
    return { ok: false, created: false, message: "RUT_APODERADO_INVALID" };
  }

  const db = getDb();

  // 1) Si ya existe: no hacemos nada (NO pisamos password)
  const [existRows] = await db.query<any[]>(
    `SELECT rut_apoderado
     FROM apoderados_auth
     WHERE rut_apoderado = ?
     LIMIT 1`,
    [rut8]
  );

  if (existRows?.length) {
    return { ok: true, created: false, rut_apoderado: rut8 };
  }

  // 2) No existe -> creamos con hash
  const hash = await argon2.hash(provisionalPlainPassword);

  await db.query(
    `INSERT INTO apoderados_auth
      (rut_apoderado, password_hash, must_change_password, estado_id, created_at, updated_at)
     VALUES
      (?, ?, 1, 1, NOW(), NOW())`,
    [rut8, hash]
  );

  return { ok: true, created: true, rut_apoderado: rut8 };
}

//UPDATE apoderados_auth
//SET password_hash = '$argon2id$v=19$m=19456,t=2,p=1$GHvmaHaLIOy8qlKfedgaOA$VTTKy9Orp7AV3Ymq84ZVR/I1B7iqcgl6ZxyqxphodMs',
//    must_change_password = 1,
    //updated_at = NOW()
//WHERE rut_apoderado = '16978094'
