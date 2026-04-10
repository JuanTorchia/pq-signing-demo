/**
 * Runner interactivo — todos los demos en secuencia.
 * Uso: npm run demo
 */

import { SoftwareHSM } from "./hsm/software-hsm.js"
import { signDocument, verifyDocument } from "./demos/sign-document.js"
import { issueJwt, verifyJwt } from "./demos/sign-jwt.js"

const BOLD   = "\x1b[1m"
const CYAN   = "\x1b[36m"
const GREEN  = "\x1b[32m"
const YELLOW = "\x1b[33m"
const DIM    = "\x1b[2m"
const RESET  = "\x1b[0m"

const hsm = new SoftwareHSM()
const info = hsm.info()

console.log(`
${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗
║         Post-Quantum Signing Demo — juanchi.dev      ║
╚══════════════════════════════════════════════════════╝${RESET}

${BOLD}Software HSM inicializado:${RESET}
  Modelo:     ${info.model}
  Firmware:   ${info.firmwareVersion}
  Algoritmos: ${info.algorithms.join(", ")}
  FIPS mode:  ${info.fipsMode ? "✅ Sí" : DIM + "❌ No (software sim)" + RESET}
`)

// ── 1. HSM info ───────────────────────────────────────────────────────────
console.log(`${BOLD}${CYAN}── 1. Generación de claves en el HSM ──────────────────────${RESET}`)

const algorithms = ["ecdsa-p256", "ml-dsa-65", "hybrid-p256-mldsa65"] as const
for (const alg of algorithms) {
  const kp = await hsm.generateKeyPair(alg, `demo-${alg}`)
  const color = alg === "ecdsa-p256" ? YELLOW : CYAN
  console.log(`  ${color}${alg.padEnd(24)}${RESET} keyId: ${DIM}${kp.keyId.slice(0, 32)}${RESET}`)
  console.log(`  ${"".padEnd(24)} pubKey: ${kp.publicKey.length} bytes`)
}

console.log(`\n  ${DIM}Keys almacenadas: ${hsm.listKeys().length}${RESET}`)
console.log(`  ${DIM}Claves privadas: NUNCA salen del HSM${RESET}\n`)

// ── 2. Firma de documento ─────────────────────────────────────────────────
console.log(`${BOLD}${CYAN}── 2. Firma de Documento ──────────────────────────────────${RESET}`)

const doc = "Acuerdo de nivel de servicio — juanchi.dev — Abril 2026"

const ecdsaDoc = await signDocument(doc, "ecdsa-p256")
const mldsaDoc = await signDocument(doc, "ml-dsa-65")

console.log(`  ${YELLOW}ECDSA P-256:${RESET}    ${ecdsaDoc.signature.length / 2} bytes de firma`)
console.log(`  ${CYAN}ML-DSA-65:${RESET}      ${mldsaDoc.signature.length / 2} bytes de firma`)

const ecOk = await verifyDocument(ecdsaDoc)
const pqOk = await verifyDocument(mldsaDoc)
console.log(`  Verificación ECDSA:   ${ecOk ? GREEN + "✅ válida" : "❌ inválida"}${RESET}`)
console.log(`  Verificación ML-DSA:  ${pqOk ? GREEN + "✅ válida" : "❌ inválida"}${RESET}\n`)

// ── 3. JWT post-quantum ───────────────────────────────────────────────────
console.log(`${BOLD}${CYAN}── 3. JWT con ML-DSA-65 ───────────────────────────────────${RESET}`)

const jwt = await issueJwt({ sub: "user_123", iss: "https://juanchi.dev", role: "admin" })
const jwtVerify = await verifyJwt(jwt.token, jwt.keyId)

console.log(`  Token emitido:    ${DIM}${jwt.token.slice(0, 60)}...${RESET}`)
console.log(`  Tamaño del token: ${jwt.token.length} chars`)
console.log(`  Verificación:     ${jwtVerify.valid ? GREEN + "✅ válido" : "❌ inválido"}${RESET}`)
console.log(`  Subject:          ${jwtVerify.payload?.sub}`)
console.log(`  Role:             ${jwtVerify.payload?.["role"]}\n`)

// ── 4. Comparativa rápida de tamaños ─────────────────────────────────────
console.log(`${BOLD}${CYAN}── 4. Comparativa de Tamaños ──────────────────────────────${RESET}`)
console.log(`
  ${"Algoritmo".padEnd(20)} ${"Firma".padStart(8)} ${"PubKey".padStart(8)}  Quantum-safe
  ${"─".repeat(55)}
  ${YELLOW}${"ecdsa-p256".padEnd(20)}${RESET} ${String(ecdsaDoc.signature.length / 2).padStart(7)}B ${String(ecdsaDoc.publicKey.length / 2).padStart(7)}B  ❌
  ${CYAN}${"ml-dsa-65".padEnd(20)}${RESET} ${String(mldsaDoc.signature.length / 2).padStart(7)}B ${String(mldsaDoc.publicKey.length / 2).padStart(7)}B  ✅ (FIPS 204)
`)

console.log(`${GREEN}${BOLD}✅ Demo completado — repo: github.com/JuanTorchia/pq-signing-demo${RESET}
${DIM}Post: juanchi.dev/blog/nist-post-quantum-firma-digital-hsm-migracion${RESET}
`)
