/**
 * Demo: firma de documentos con el SoftwareHSM.
 * Simula el flujo real de una firma digital:
 *   1. El HSM genera y guarda las claves (nunca las expone)
 *   2. La aplicación pasa el documento para firmar
 *   3. El HSM firma internamente y devuelve solo la firma
 *   4. Cualquiera puede verificar con la clave pública
 */

import { sha256 } from "@noble/hashes/sha256"
import { SoftwareHSM } from "../hsm/software-hsm.js"
import type { Algorithm } from "../hsm/types.js"

const hsm = new SoftwareHSM()

export interface SignedDocument {
  content: string
  contentHash: string        // SHA-256 del contenido (lo que realmente se firma)
  signature: string          // hex
  publicKey: string          // hex — para que el receptor verifique
  algorithm: Algorithm
  keyId: string
  signedAt: string
}

/**
 * Firma un documento y retorna el paquete de firma verificable.
 * La clave privada nunca sale del HSM.
 */
export async function signDocument(
  content: string,
  algorithm: Algorithm
): Promise<SignedDocument> {
  // 1. Generar (o recuperar) la clave en el HSM
  const kp = await hsm.generateKeyPair(algorithm, "doc-signing-key")

  // 2. Hash del contenido — firmamos el hash, no el contenido entero
  const contentBytes = new TextEncoder().encode(content)
  const hash = sha256(contentBytes)

  // 3. El HSM firma el hash — la clave privada nunca sale
  const { signature } = await hsm.sign(kp.keyId, hash)

  return {
    content,
    contentHash: Buffer.from(hash).toString("hex"),
    signature: Buffer.from(signature).toString("hex"),
    publicKey: Buffer.from(kp.publicKey).toString("hex"),
    algorithm,
    keyId: kp.keyId,
    signedAt: new Date().toISOString(),
  }
}

/**
 * Verifica un documento firmado.
 * Solo necesita la clave pública — la privada se queda en el HSM.
 */
export async function verifyDocument(doc: SignedDocument): Promise<boolean> {
  const contentBytes = new TextEncoder().encode(doc.content)
  const hash = sha256(contentBytes)

  // Verificar que el hash coincide
  const expectedHash = Buffer.from(hash).toString("hex")
  if (expectedHash !== doc.contentHash) {
    console.error("  ❌ El hash del contenido no coincide — documento alterado")
    return false
  }

  const sig = Uint8Array.from(Buffer.from(doc.signature, "hex"))
  const result = await hsm.verify(doc.keyId, hash, sig)
  return result.valid
}

// ── Demo ─────────────────────────────────────────────────────────────────────

if (import.meta.url === `file://${process.argv[1]}`) {
  const GREEN  = "\x1b[32m"
  const CYAN   = "\x1b[36m"
  const BOLD   = "\x1b[1m"
  const DIM    = "\x1b[2m"
  const YELLOW = "\x1b[33m"
  const RESET  = "\x1b[0m"

  console.log(`\n${BOLD}${CYAN}── Demo: Firma de Documentos ──${RESET}\n`)

  const documento = `
CONTRATO DE SERVICIOS TECNOLÓGICOS

Entre Juan Torchia (en adelante "el Proveedor") y el Cliente,
se acuerda la prestación de servicios de desarrollo de software.

Fecha: ${new Date().toLocaleDateString("es-AR")}
Monto: $5.000 USD
Plazo: 3 meses

Firmado digitalmente con criptografía post-quantum ML-DSA-65 (FIPS 204).
`.trim()

  // Firmar con ECDSA clásico
  console.log(`${YELLOW}Firmando con ECDSA P-256 (clásico)...${RESET}`)
  const ecdsaDoc = await signDocument(documento, "ecdsa-p256")
  console.log(`  Firma:     ${ecdsaDoc.signature.slice(0, 40)}...`)
  console.log(`  Tamaño:    ${BOLD}${ecdsaDoc.signature.length / 2}${RESET} bytes`)

  const ecdsaValid = await verifyDocument(ecdsaDoc)
  console.log(`  Válida:    ${ecdsaValid ? GREEN + "✅ Sí" : "❌ No"}${RESET}\n`)

  // Firmar con ML-DSA-65 (post-quantum)
  console.log(`${CYAN}Firmando con ML-DSA-65 (post-quantum, FIPS 204)...${RESET}`)
  const mldsaDoc = await signDocument(documento, "ml-dsa-65")
  console.log(`  Firma:     ${mldsaDoc.signature.slice(0, 40)}...`)
  console.log(`  Tamaño:    ${BOLD}${mldsaDoc.signature.length / 2}${RESET} bytes`)

  const mldsaValid = await verifyDocument(mldsaDoc)
  console.log(`  Válida:    ${mldsaValid ? GREEN + "✅ Sí" : "❌ No"}${RESET}\n`)

  // Firmar con modo híbrido (transición)
  console.log(`${YELLOW}Firmando con Híbrido P-256 + ML-DSA-65 (modo transición)...${RESET}`)
  const hybridDoc = await signDocument(documento, "hybrid-p256-mldsa65")
  console.log(`  Firma:     ${hybridDoc.signature.slice(0, 40)}...`)
  console.log(`  Tamaño:    ${BOLD}${hybridDoc.signature.length / 2}${RESET} bytes  ${DIM}(ECDSA + ML-DSA concatenadas)${RESET}`)

  const hybridValid = await verifyDocument(hybridDoc)
  console.log(`  Válida:    ${hybridValid ? GREEN + "✅ Sí" : "❌ No"}${RESET}\n`)

  // Tamper test — modificar el documento y verificar que falla
  console.log(`${DIM}── Test de integridad: modificar el documento ─${RESET}`)
  const tampered = { ...mldsaDoc, content: mldsaDoc.content + " [ALTERADO]" }
  const tamperedValid = await verifyDocument(tampered)
  console.log(`  Documento alterado detectado: ${!tamperedValid ? GREEN + "✅ Sí (firma inválida)" : "❌ No detectado"}${RESET}\n`)
}
