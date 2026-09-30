import "dotenv/config";

import {
  validateCryptoConfiguration,
  cryptoSelfTest,
  encryptRut,
  decryptRut,
  rutBlindIndex,
  encryptField,
  decryptField,
} from "../services/crypto";

function main() {
  console.log("=== WELI CRYPTO TEST ===");

  validateCryptoConfiguration();
  console.log("✅ Configuración criptográfica válida");

  cryptoSelfTest();
  console.log("✅ Self-test correcto");

  const rut = "12345678";

  const encryptedRutA = encryptRut(rut);
  const encryptedRutB = encryptRut(rut);

  const decryptedRut = decryptRut(encryptedRutA);

  const indexA = rutBlindIndex(rut);
  const indexB = rutBlindIndex(rut);

  console.log("\n--- RUT ---");
  console.log("RUT original:", rut);
  console.log("RUT cifrado A:", encryptedRutA);
  console.log("RUT cifrado B:", encryptedRutB);
  console.log("RUT descifrado:", decryptedRut);

  console.log("\n--- BLIND INDEX ---");
  console.log("Index A:", indexA);
  console.log("Index B:", indexB);

  console.log("\n--- VALIDACIONES ---");

  console.log(
    "Ciphertexts distintos:",
    encryptedRutA !== encryptedRutB
  );

  console.log(
    "Blind indexes iguales:",
    indexA === indexB
  );

  console.log(
    "RUT recuperado correctamente:",
    decryptedRut === rut
  );

  const nombre = "Jugador de Prueba";

  const encryptedName = encryptField(nombre);
  const decryptedName = decryptField(encryptedName);

  console.log("\n--- CAMPO GENÉRICO ---");
  console.log("Nombre original:", nombre);
  console.log("Nombre cifrado:", encryptedName);
  console.log("Nombre descifrado:", decryptedName);

  console.log("\n✅ PRUEBA FINALIZADA");
}

try {
  main();
} catch (error) {
  console.error("\n❌ FALLÓ LA PRUEBA CRIPTOGRÁFICA");

  if (error instanceof Error) {
    console.error(error.name);
    console.error(error.message);
  } else {
    console.error("Error desconocido");
  }

  process.exit(1);
}