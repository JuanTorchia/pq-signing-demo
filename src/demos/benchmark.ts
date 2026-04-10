/**
 * Benchmark: tamaños y tiempos de firma.
 * Muestra exactamente por qué ML-DSA no es un drop-in de ECDSA
 * y qué trade-offs tenés que considerar.
 *
 * Uso: npm run benchmark
 */

import { SoftwareHSM } from "../hsm/software-hsm.js"
import type { Algorithm } from "../hsm/types.js"

const hsm = new SoftwareHSM()
const ITERATIONS = 20
const DOC = new TextEncoder().encode(
  "Documento de prueba: este texto simula el hash de un contrato legal."
)

const BOLD  = "\x1b[1m"
const CYAN  = "\x1b[36m"
const GREEN = "\x1b[32m"
const YELLOW= "\x1b[33m"
const RED   = "\x1b[31m"
const DIM   = "\x1b[2m"
const RESET = "\x1b[0m"

interface BenchResult {
  algorithm: Algorithm
  pubKeyBytes: number
  privKeyBytes: number
  signatureBytes: number
  keygenMs: number
  signMs: number
  verifyMs: number
  verified: boolean
}

async function bench(algorithm: Algorithm): Promise<BenchResult> {
  // Keygen
  const t0 = performance.now()
  const kp  = await hsm.generateKeyPair(algorithm, `bench-${algorithm}`)
  const keygenMs = (performance.now() - t0)

  // Sign (promedio de N iteraciones)
  let totalSign = 0
  let lastSig = new Uint8Array()
  for (let i = 0; i < ITERATIONS; i++) {
    const ts = performance.now()
    const result = await hsm.sign(kp.keyId, DOC)
    totalSign += performance.now() - ts
    lastSig = result.signature
  }

  // Verify (promedio de N iteraciones)
  let totalVerify = 0
  let verified = false
  for (let i = 0; i < ITERATIONS; i++) {
    const tv = performance.now()
    const result = await hsm.verify(kp.keyId, DOC, lastSig)
    totalVerify += performance.now() - tv
    verified = result.valid
  }

  // Tamaño de clave privada — acceso interno solo para el benchmark
  // En un HSM real esto no sería posible
  const privKeyBytes = (algorithm === "ecdsa-p256") ? 32
    : (algorithm === "ml-dsa-44")  ? 2560
    : (algorithm === "ml-dsa-65")  ? 4032
    : (algorithm === "ml-dsa-87")  ? 4896
    : (algorithm === "slh-dsa-sha2-128s") ? 64
    : (algorithm === "hybrid-p256-mldsa65") ? 32 + 4032
    : 0

  return {
    algorithm,
    pubKeyBytes: kp.publicKey.length,
    privKeyBytes,
    signatureBytes: lastSig.length,
    keygenMs: keygenMs,
    signMs: totalSign / ITERATIONS,
    verifyMs: totalVerify / ITERATIONS,
    verified,
  }
}

function bar(value: number, max: number, width = 30): string {
  const filled = Math.round((value / max) * width)
  return "█".repeat(filled) + "░".repeat(width - filled)
}

async function main() {
  console.log(`\n${BOLD}${CYAN}Post-Quantum Signing Benchmark${RESET}`)
  console.log(`${DIM}Usando SoftwareHSM — ${ITERATIONS} iteraciones por algoritmo${RESET}\n`)

  const algorithms: Algorithm[] = [
    "ecdsa-p256",
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    "slh-dsa-sha2-128s",
    "hybrid-p256-mldsa65",
  ]

  const results: BenchResult[] = []
  for (const alg of algorithms) {
    process.stdout.write(`  Benchmarking ${alg}...`)
    const r = await bench(alg)
    results.push(r)
    process.stdout.write(` ✅\n`)
  }

  // ── Tamaño de firma ──────────────────────────────────────────────────────
  console.log(`\n${BOLD}── Tamaño de Firma ──────────────────────────────────────────${RESET}`)
  const maxSig = Math.max(...results.map(r => r.signatureBytes))

  for (const r of results) {
    const label = r.algorithm.padEnd(22)
    const bytes = String(r.signatureBytes).padStart(6)
    const ratio = (r.signatureBytes / (results[0]?.signatureBytes ?? 1)).toFixed(1)
    const color = r.algorithm === "ecdsa-p256" ? GREEN
      : r.algorithm.startsWith("hybrid") ? YELLOW : CYAN
    console.log(`  ${color}${label}${RESET} ${bar(r.signatureBytes, maxSig)} ${BOLD}${bytes}${RESET} bytes  ${DIM}(${ratio}x)${RESET}`)
  }

  // ── Tamaño de clave pública ──────────────────────────────────────────────
  console.log(`\n${BOLD}── Clave Pública ────────────────────────────────────────────${RESET}`)
  const maxPub = Math.max(...results.map(r => r.pubKeyBytes))

  for (const r of results) {
    const label = r.algorithm.padEnd(22)
    const bytes = String(r.pubKeyBytes).padStart(6)
    const color = r.algorithm === "ecdsa-p256" ? GREEN
      : r.algorithm.startsWith("hybrid") ? YELLOW : CYAN
    console.log(`  ${color}${label}${RESET} ${bar(r.pubKeyBytes, maxPub)} ${BOLD}${bytes}${RESET} bytes`)
  }

  // ── Tiempos ──────────────────────────────────────────────────────────────
  console.log(`\n${BOLD}── Tiempo de Firma (promedio ${ITERATIONS} iteraciones) ─────────────${RESET}`)
  const maxSign = Math.max(...results.map(r => r.signMs))

  for (const r of results) {
    const label = r.algorithm.padEnd(22)
    const ms    = r.signMs.toFixed(2).padStart(7)
    const color = r.algorithm === "ecdsa-p256" ? GREEN
      : r.algorithm.startsWith("hybrid") ? YELLOW : CYAN
    console.log(`  ${color}${label}${RESET} ${bar(r.signMs, maxSign)} ${BOLD}${ms}${RESET} ms`)
  }

  // ── Tiempos de verificación ───────────────────────────────────────────────
  console.log(`\n${BOLD}── Tiempo de Verificación (promedio ${ITERATIONS} iteraciones) ─────${RESET}`)
  const maxVerify = Math.max(...results.map(r => r.verifyMs))

  for (const r of results) {
    const label  = r.algorithm.padEnd(22)
    const ms     = r.verifyMs.toFixed(2).padStart(7)
    const ok     = r.verified ? `${GREEN}✅${RESET}` : `${RED}❌${RESET}`
    const color  = r.algorithm === "ecdsa-p256" ? GREEN
      : r.algorithm.startsWith("hybrid") ? YELLOW : CYAN
    console.log(`  ${color}${label}${RESET} ${bar(r.verifyMs, maxVerify)} ${BOLD}${ms}${RESET} ms  ${ok}`)
  }

  // ── Resumen ───────────────────────────────────────────────────────────────
  const ecdsa = results.find(r => r.algorithm === "ecdsa-p256")!
  const mldsa = results.find(r => r.algorithm === "ml-dsa-65")!

  console.log(`\n${BOLD}── Resumen: ECDSA P-256 vs ML-DSA-65 ───────────────────────${RESET}`)
  console.log(`  Tamaño de firma:   ${BOLD}${ecdsa.signatureBytes}${RESET} bytes → ${BOLD}${CYAN}${mldsa.signatureBytes}${RESET} bytes  (${CYAN}${(mldsa.signatureBytes / ecdsa.signatureBytes).toFixed(0)}x más grande${RESET})`)
  console.log(`  Clave pública:     ${BOLD}${ecdsa.pubKeyBytes}${RESET} bytes → ${BOLD}${CYAN}${mldsa.pubKeyBytes}${RESET} bytes  (${CYAN}${(mldsa.pubKeyBytes / ecdsa.pubKeyBytes).toFixed(0)}x más grande${RESET})`)
  console.log(`  Tiempo de firma:   ${BOLD}${ecdsa.signMs.toFixed(2)}${RESET} ms    → ${BOLD}${CYAN}${mldsa.signMs.toFixed(2)}${RESET} ms`)
  console.log(`  Verificación:      ${BOLD}${ecdsa.verifyMs.toFixed(2)}${RESET} ms    → ${BOLD}${CYAN}${mldsa.verifyMs.toFixed(2)}${RESET} ms`)

  console.log(`
${DIM}Nota: estos tiempos son del SoftwareHSM en memoria.
Un HSM de hardware tiene latencia adicional por la comunicación PKCS#11 (~1-5ms/op).
ML-DSA tiene firmas más grandes pero tiempos competitivos — no hay excusa de performance.${RESET}
`)
}

main().catch(e => { console.error(e); process.exit(1) })
