/**
 * Demo: JWT post-quantum con ML-DSA-65.
 *
 * Los JWT estándar usan ES256 (ECDSA P-256) o RS256 (RSA).
 * Ambos van a ser vulnerables a Shor's algorithm.
 * Este demo implementa un formato compatible que usa ML-DSA-65
 * siguiendo el borrador de IANA para PQ algorithm identifiers en JWA.
 *
 * Algorithm identifier: "ML-DSA-65" (borrador IETF)
 * Referencia: draft-ietf-cose-dilithium
 */

import { sha256 } from "@noble/hashes/sha256"
import { SoftwareHSM } from "../hsm/software-hsm.js"

const hsm = new SoftwareHSM()

function base64url(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "")
}

function base64urlDecode(str: string): Uint8Array {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/")
  return Uint8Array.from(Buffer.from(b64, "base64"))
}

export interface PQJwtPayload {
  sub: string          // subject
  iss: string          // issuer
  iat: number          // issued at (unix timestamp)
  exp: number          // expiration
  [key: string]: unknown
}

export interface PQJwt {
  token: string        // header.payload.signature (base64url)
  algorithm: string
  keyId: string
  publicKey: string    // hex — para incluir en el JWKS
}

/**
 * Emite un JWT firmado con ML-DSA-65.
 * La clave privada se mantiene en el SoftwareHSM.
 */
export async function issueJwt(
  payload: Omit<PQJwtPayload, "iat" | "exp">,
  expiresInSeconds = 3600
): Promise<PQJwt> {
  const kp = await hsm.generateKeyPair("ml-dsa-65", "jwt-signing-key")

  const header = { alg: "ML-DSA-65", typ: "JWT", kid: kp.keyId }
  const fullPayload: PQJwtPayload = {
    ...payload,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expiresInSeconds,
  }

  const headerB64  = base64url(JSON.stringify(header))
  const payloadB64 = base64url(JSON.stringify(fullPayload))
  const signingInput = `${headerB64}.${payloadB64}`

  // Firmamos el hash SHA-256 del signing input (header.payload)
  const hash = sha256(new TextEncoder().encode(signingInput))
  const { signature } = await hsm.sign(kp.keyId, hash)

  const sigB64 = base64url(signature)
  const token  = `${signingInput}.${sigB64}`

  return {
    token,
    algorithm: "ML-DSA-65",
    keyId: kp.keyId,
    publicKey: Buffer.from(kp.publicKey).toString("hex"),
  }
}

export interface JwtVerifyResult {
  valid: boolean
  payload?: PQJwtPayload
  error?: string
}

/**
 * Verifica un JWT con ML-DSA-65.
 * Necesita el keyId para encontrar la clave pública en el HSM.
 */
export async function verifyJwt(token: string, keyId: string): Promise<JwtVerifyResult> {
  const parts = token.split(".")
  if (parts.length !== 3) return { valid: false, error: "Formato JWT inválido" }

  const [headerB64, payloadB64, sigB64] = parts as [string, string, string]

  let header: { alg: string; kid: string }
  let payload: PQJwtPayload
  try {
    header  = JSON.parse(Buffer.from(base64urlDecode(headerB64)).toString())
    payload = JSON.parse(Buffer.from(base64urlDecode(payloadB64)).toString())
  } catch {
    return { valid: false, error: "JWT malformado" }
  }

  if (header.alg !== "ML-DSA-65") {
    return { valid: false, error: `Algoritmo no soportado: ${header.alg}` }
  }

  // Verificar expiración
  if (payload.exp < Math.floor(Date.now() / 1000)) {
    return { valid: false, error: "JWT expirado" }
  }

  const signingInput = `${headerB64}.${payloadB64}`
  const hash = sha256(new TextEncoder().encode(signingInput))
  const signature = base64urlDecode(sigB64)

  const result = await hsm.verify(keyId, hash, signature)

  return result.valid
    ? { valid: true, payload }
    : { valid: false, error: "Firma inválida" }
}

// ── Demo ─────────────────────────────────────────────────────────────────────

if (import.meta.url === `file://${process.argv[1]}`) {
  const GREEN  = "\x1b[32m"
  const CYAN   = "\x1b[36m"
  const BOLD   = "\x1b[1m"
  const DIM    = "\x1b[2m"
  const RED    = "\x1b[31m"
  const RESET  = "\x1b[0m"

  console.log(`\n${BOLD}${CYAN}── Demo: JWT Post-Quantum ──${RESET}\n`)

  const jwt = await issueJwt({
    sub: "user_juan123",
    iss: "https://juanchi.dev",
    role: "admin",
    email: "juan@juanchi.dev",
  }, 3600)

  console.log(`${BOLD}JWT emitido con ML-DSA-65:${RESET}`)
  console.log(`  ${DIM}${jwt.token.slice(0, 80)}...${RESET}`)
  console.log(`  Tamaño del token:  ${BOLD}${jwt.token.length}${RESET} chars`)
  console.log(`  ${DIM}(vs ~250 chars de un JWT ES256 típico)${RESET}`)
  console.log(`  Clave pública (para JWKS): ${jwt.publicKey.slice(0, 40)}...`)
  console.log(`  Tamaño clave pública:      ${BOLD}${jwt.publicKey.length / 2}${RESET} bytes\n`)

  // Verificar JWT válido
  const validResult = await verifyJwt(jwt.token, jwt.keyId)
  console.log(`${BOLD}Verificación JWT válido:${RESET}`)
  console.log(`  Válido: ${validResult.valid ? GREEN + "✅ Sí" : RED + "❌ No"}${RESET}`)
  if (validResult.payload) {
    console.log(`  Sub:    ${validResult.payload.sub}`)
    console.log(`  Role:   ${validResult.payload["role"]}`)
    console.log(`  Exp:    ${new Date((validResult.payload.exp as number) * 1000).toLocaleString("es-AR")}`)
  }

  // Verificar JWT adulterado — cambiar el payload a mano
  console.log(`\n${DIM}── Test de integridad: adulterar el payload ─${RESET}`)
  const parts = jwt.token.split(".")
  const fakePayload = base64url(JSON.stringify({
    sub: "user_hacker",
    iss: "https://juanchi.dev",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 9999,
    role: "admin",
  }))
  const tamperedToken = `${parts[0]}.${fakePayload}.${parts[2]}`
  const tamperedResult = await verifyJwt(tamperedToken, jwt.keyId)
  console.log(`  JWT adulterado detectado: ${!tamperedResult.valid ? GREEN + "✅ Sí (firma inválida)" : RED + "❌ No detectado"}${RESET}`)

  console.log(`\n${DIM}Nota: el tamaño del token JWT con ML-DSA-65 es ~5KB vs ~250 bytes de ES256.
Si emitís millones de tokens por día, ese overhead importa.
La recomendación actual es usar ML-DSA para tokens de larga vida (certificados,
document signing) y esperar a ML-DSA-44 o FN-DSA para tokens de corta vida.${RESET}\n`)
}
