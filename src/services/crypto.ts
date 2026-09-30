// src/services/crypto.ts

import crypto from "node:crypto";

/* =========================================================
   CONFIGURACIÓN
========================================================= */

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;

const CIPHER_VERSION = "v1";
const FIELD_SEPARATOR = ".";

const ENCRYPTION_ENV_NAME = "WELI_DATA_ENCRYPTION_KEY";
const INDEX_ENV_NAME = "WELI_DATA_INDEX_KEY";

/* =========================================================
   ERRORES CONTROLADOS
========================================================= */

export class CryptoServiceError extends Error {
  public readonly code: string;

  constructor(code: string, message = "Error criptográfico") {
    super(message);

    this.name = "CryptoServiceError";
    this.code = code;
  }
}

/* =========================================================
   HELPERS GENERALES
========================================================= */

function ensureString(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }

  if (typeof value !== "string" && typeof value !== "number" && typeof value !== "bigint") {
    throw new CryptoServiceError("INVALID_INPUT", "El valor recibido no es válido.");
  }

  return String(value);
}

function ensureNonEmptyString(value: unknown, fieldName = "valor"): string {
  const normalized = ensureString(value).trim();

  if (!normalized) {
    throw new CryptoServiceError("EMPTY_VALUE", `El ${fieldName} no puede estar vacío.`);
  }

  return normalized;
}

function decodeBase64Strict(value: string, fieldName: string): Buffer {
  const normalized = String(value || "").trim();

  if (!normalized) {
    throw new CryptoServiceError("INVALID_CIPHERTEXT", `El componente ${fieldName} está vacío.`);
  }

  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)) {
    throw new CryptoServiceError("INVALID_CIPHERTEXT", `El componente ${fieldName} no tiene un formato válido.`);
  }

  const buffer = Buffer.from(normalized, "base64");

  if (!buffer.length) {
    throw new CryptoServiceError("INVALID_CIPHERTEXT", `El componente ${fieldName} no pudo decodificarse.`);
  }

  return buffer;
}

function parseKeyFromEnv(envName: string, expectedBytes: number): Buffer {
  const raw = process.env[envName];

  if (!raw) {
    throw new CryptoServiceError("MISSING_KEY", `Falta configurar ${envName}.`);
  }

  const value = raw.trim();

  /*
   * Formatos permitidos:
   *
   * 1) Base64
   * 2) Hexadecimal
   *
   * No aceptamos texto arbitrario porque una clave de cifrado
   * debe tener exactamente 32 bytes reales.
   */

  if (/^[0-9a-fA-F]+$/.test(value) && value.length === expectedBytes * 2) {
    const key = Buffer.from(value, "hex");

    if (key.length !== expectedBytes) {
      throw new CryptoServiceError(
        "INVALID_KEY_LENGTH",
        `${envName} debe contener exactamente ${expectedBytes} bytes.`
      );
    }

    return key;
  }

  try {
    const key = Buffer.from(value, "base64");

    if (key.length !== expectedBytes) {
      throw new CryptoServiceError(
        "INVALID_KEY_LENGTH",
        `${envName} debe contener exactamente ${expectedBytes} bytes.`
      );
    }

    return key;
  } catch (error) {
    if (error instanceof CryptoServiceError) {
      throw error;
    }

    throw new CryptoServiceError("INVALID_KEY", `${envName} tiene un formato inválido.`);
  }
}

/* =========================================================
   CARGA DE CLAVES
========================================================= */

function getEncryptionKey(): Buffer {
  return parseKeyFromEnv(ENCRYPTION_ENV_NAME, KEY_LENGTH);
}

function getIndexKey(): Buffer {
  return parseKeyFromEnv(INDEX_ENV_NAME, KEY_LENGTH);
}

/* =========================================================
   NORMALIZACIÓN DE RUT
========================================================= */

/**
 * Regla interna WELI:
 *
 * - exactamente 8 dígitos
 * - sin puntos
 * - sin guion
 * - sin dígito verificador
 *
 * Ejemplo visual:
 * 12.345.678-5
 *
 * Internamente:
 * 12345678
 */
export function normalizeRut(value: unknown): string {
  const raw = ensureString(value);
  const digits = raw.replace(/\D/g, "");

  if (!/^\d{7,8}$/.test(digits)) {
    throw new CryptoServiceError("INVALID_RUT", "El RUT debe contener 7 u 8 dígitos, sin dígito verificador.");
  }

  return digits;
}

/* =========================================================
   CIFRADO AES-256-GCM
========================================================= */

/**
 * Formato almacenado:
 *
 * v1.<iv-base64>.<auth-tag-base64>.<ciphertext-base64>
 *
 * Ejemplo:
 *
 * v1.kJ3...=.A9c...=.jK82...
 *
 * Cada cifrado utiliza un IV aleatorio nuevo.
 */
export function encryptField(value: unknown): string {
  const plaintext = ensureNonEmptyString(value, "dato a cifrar");

  const key = getEncryptionKey();

  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);

  const authTag = cipher.getAuthTag();

  return [CIPHER_VERSION, iv.toString("base64"), authTag.toString("base64"), encrypted.toString("base64")].join(
    FIELD_SEPARATOR
  );
}

/* =========================================================
   DESCIFRADO AES-256-GCM
========================================================= */

export function decryptField(value: unknown): string {
  const payload = ensureNonEmptyString(value, "dato cifrado");

  const parts = payload.split(FIELD_SEPARATOR);

  if (parts.length !== 4) {
    throw new CryptoServiceError("INVALID_CIPHERTEXT", "El dato cifrado tiene un formato inválido.");
  }

  const [version, ivB64, authTagB64, ciphertextB64] = parts;

  if (version !== CIPHER_VERSION) {
    throw new CryptoServiceError("UNSUPPORTED_VERSION", "La versión del dato cifrado no es compatible.");
  }

  const iv = decodeBase64Strict(ivB64, "iv");

  const authTag = decodeBase64Strict(authTagB64, "authTag");

  const ciphertext = decodeBase64Strict(ciphertextB64, "ciphertext");

  if (iv.length !== IV_LENGTH) {
    throw new CryptoServiceError("INVALID_CIPHERTEXT", "El IV tiene una longitud inválida.");
  }

  if (authTag.length !== AUTH_TAG_LENGTH) {
    throw new CryptoServiceError("INVALID_CIPHERTEXT", "El tag de autenticación tiene una longitud inválida.");
  }

  const key = getEncryptionKey();

  try {
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    return decrypted.toString("utf8");
  } catch {
    /*
     * No exponemos detalles internos porque podrían
     * ayudar a un atacante a distinguir errores
     * de clave, tag o contenido.
     */
    throw new CryptoServiceError("DECRYPT_FAILED", "No fue posible descifrar el dato.");
  }
}

/* =========================================================
   BLIND INDEX
========================================================= */

/**
 * Genera un índice determinista mediante HMAC-SHA256.
 *
 * IMPORTANTE:
 *
 * - NO permite recuperar el dato original.
 * - Sirve para búsquedas exactas.
 * - Debe usarse únicamente sobre valores normalizados.
 */
export function blindIndex(value: unknown): string {
  const normalized = ensureNonEmptyString(value, "dato para índice");

  const key = getIndexKey();

  return crypto.createHmac("sha256", key).update(normalized, "utf8").digest("hex");
}

/* =========================================================
   BLIND INDEX DE RUT
========================================================= */

export function rutBlindIndex(value: unknown): string {
  return blindIndex(normalizeRut(value));
}

/* =========================================================
   CIFRADO DE RUT
========================================================= */

export function encryptRut(value: unknown): string {
  return encryptField(normalizeRut(value));
}

export function decryptRut(value: unknown): string {
  const decrypted = decryptField(value);

  return normalizeRut(decrypted);
}

/* =========================================================
   CIFRADO OPCIONAL
========================================================= */

/**
 * Útil para columnas nullable.
 *
 * null / undefined / ""
 * → null
 */
export function encryptNullable(value: unknown): string | null {
  if (value === null || value === undefined) {
    return null;
  }

  const normalized = ensureString(value).trim();

  if (!normalized) {
    return null;
  }

  return encryptField(normalized);
}

export function decryptNullable(value: unknown): string | null {
  if (value === null || value === undefined) {
    return null;
  }

  const normalized = ensureString(value).trim();

  if (!normalized) {
    return null;
  }

  return decryptField(normalized);
}

/* =========================================================
   MASKING
========================================================= */

export function maskRut(value: unknown): string {
  let rut: string;

  try {
    rut = normalizeRut(value);
  } catch {
    return "********";
  }

  return `${rut.slice(0, 2)}.***.***`;
}

export function maskEmail(value: unknown): string {
  const email = ensureString(value).trim().toLowerCase();

  if (!email) {
    return "";
  }

  const at = email.indexOf("@");

  if (at <= 0) {
    return "***";
  }

  const local = email.slice(0, at);
  const domain = email.slice(at + 1);

  if (!domain) {
    return "***";
  }

  const localVisible = local.length <= 2 ? local.slice(0, 1) : local.slice(0, 2);

  return `${localVisible}***@${domain}`;
}

export function maskPhone(value: unknown): string {
  const raw = ensureString(value).trim();

  if (!raw) {
    return "";
  }

  const digits = raw.replace(/\D/g, "");

  if (digits.length < 4) {
    return "****";
  }

  return `****${digits.slice(-4)}`;
}

export function maskName(value: unknown): string {
  const name = ensureString(value).trim().replace(/\s+/g, " ");

  if (!name) {
    return "";
  }

  return name
    .split(" ")
    .map((part) => {
      if (!part) {
        return "";
      }

      if (part.length === 1) {
        return "*";
      }

      return `${part[0]}${"*".repeat(Math.max(1, part.length - 1))}`;
    })
    .join(" ");
}

/* =========================================================
   COMPARACIÓN CONSTANT-TIME
========================================================= */

/**
 * Útil para comparar hashes/HMACs sin depender
 * de comparación normal de strings.
 */
export function secureCompare(a: unknown, b: unknown): boolean {
  const left = Buffer.from(ensureString(a), "utf8");

  const right = Buffer.from(ensureString(b), "utf8");

  if (left.length !== right.length) {
    return false;
  }

  return crypto.timingSafeEqual(left, right);
}

/* =========================================================
   VALIDADORES
========================================================= */

export function isEncryptedValue(value: unknown): boolean {
  if (typeof value !== "string") {
    return false;
  }

  const parts = value.split(FIELD_SEPARATOR);

  return parts.length === 4 && parts[0] === CIPHER_VERSION;
}

/* =========================================================
   DIAGNÓSTICO DE CONFIGURACIÓN
========================================================= */

/**
 * Ejecutar al iniciar el backend.
 *
 * No devuelve ni imprime secretos.
 */
export function validateCryptoConfiguration(): void {
  const encryptionKey = getEncryptionKey();
  const indexKey = getIndexKey();

  if (encryptionKey.length !== KEY_LENGTH) {
    throw new CryptoServiceError("INVALID_KEY_LENGTH", `${ENCRYPTION_ENV_NAME} tiene longitud inválida.`);
  }

  if (indexKey.length !== KEY_LENGTH) {
    throw new CryptoServiceError("INVALID_KEY_LENGTH", `${INDEX_ENV_NAME} tiene longitud inválida.`);
  }

  if (crypto.timingSafeEqual(encryptionKey, indexKey)) {
    throw new CryptoServiceError("KEY_REUSE", "La clave de cifrado y la clave de índices deben ser diferentes.");
  }
}

/* =========================================================
   SELF TEST
========================================================= */

/**
 * Prueba interna segura.
 *
 * No escribe claves ni datos reales.
 * Puede ejecutarse durante startup.
 */
export function cryptoSelfTest(): boolean {
  const sample = "WELI_CRYPTO_SELF_TEST";

  const encrypted = encryptField(sample);
  const decrypted = decryptField(encrypted);

  if (decrypted !== sample) {
    throw new CryptoServiceError("SELF_TEST_FAILED", "Falló la prueba de cifrado y descifrado.");
  }

  const rut = "12345678";

  const indexA = rutBlindIndex(rut);
  const indexB = rutBlindIndex(rut);

  if (!secureCompare(indexA, indexB)) {
    throw new CryptoServiceError("SELF_TEST_FAILED", "Falló la prueba de blind index.");
  }

  return true;
}
