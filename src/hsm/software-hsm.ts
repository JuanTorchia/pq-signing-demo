/**
 * Software HSM — implementación en memoria de la interfaz HSMProvider.
 *
 * Equivalente funcional a SoftHSM2 pero con soporte para ML-DSA y SLH-DSA.
 * Las claves privadas viven en el Map interno y NUNCA se exponen al exterior —
 * el mismo modelo de seguridad que un HSM de hardware.
 *
 * Para migrar a un HSM real (Utimaco, Thales, AWS CloudHSM):
 *   1. Implementá HSMProvider usando el driver PKCS#11 del vendor
 *   2. Reemplazá SoftwareHSM por esa implementación
 *   3. El resto del código no cambia — eso es crypto-agility
 */

import { randomBytes } from "@noble/hashes/utils"
import { p256 }        from "@noble/curves/p256"
import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa"
import { slh_dsa_sha2_128s }            from "@noble/post-quantum/slh-dsa"
import type {
  HSMProvider, HSMInfo, KeyPair,
  SignatureResult, VerifyResult, Algorithm,
} from "./types.js"

/** Guarda clave privada + metadata internamente */
interface StoredKey {
  pair: KeyPair
  privateKey: Uint8Array
}

export class SoftwareHSM implements HSMProvider {
  // Las claves privadas nunca salen de este Map — mismo modelo que un HSM
  private readonly store = new Map<string, StoredKey>()

  async generateKeyPair(algorithm: Algorithm, label: string): Promise<KeyPair> {
    const keyId = `${label}-${Buffer.from(randomBytes(8)).toString("hex")}`
    let publicKey: Uint8Array
    let privateKey: Uint8Array

    switch (algorithm) {
      case "ecdsa-p256": {
        const privKey = p256.utils.randomPrivateKey()
        const pubKey  = p256.getPublicKey(privKey)
        privateKey = privKey
        publicKey  = pubKey
        break
      }
      case "ml-dsa-44": {
        const seed = randomBytes(32)
        const keys = ml_dsa44.keygen(seed)
        privateKey = keys.secretKey
        publicKey  = keys.publicKey
        break
      }
      case "ml-dsa-65": {
        const seed = randomBytes(32)
        const keys = ml_dsa65.keygen(seed)
        privateKey = keys.secretKey
        publicKey  = keys.publicKey
        break
      }
      case "ml-dsa-87": {
        const seed = randomBytes(32)
        const keys = ml_dsa87.keygen(seed)
        privateKey = keys.secretKey
        publicKey  = keys.publicKey
        break
      }
      case "slh-dsa-sha2-128s": {
        const seed = randomBytes(48)
        const keys = slh_dsa_sha2_128s.keygen(seed)
        privateKey = keys.secretKey
        publicKey  = keys.publicKey
        break
      }
      case "hybrid-p256-mldsa65": {
        // Hybrid: generamos ambas claves, concatenamos las públicas
        const ecPriv  = p256.utils.randomPrivateKey()
        const ecPub   = p256.getPublicKey(ecPriv)
        const pqKeys  = ml_dsa65.keygen(randomBytes(32))
        // Codificación: [2 bytes length][ec_pub][pq_pub]
        const lenBuf  = new Uint8Array(2)
        new DataView(lenBuf.buffer).setUint16(0, ecPub.length)
        publicKey  = concat(lenBuf, ecPub, pqKeys.publicKey)
        privateKey = concat(ecPriv, pqKeys.secretKey) // guardamos ambas privadas
        break
      }
      default:
        throw new Error(`Algoritmo no soportado: ${algorithm}`)
    }

    const pair: KeyPair = {
      keyId,
      algorithm,
      publicKey,
      createdAt: new Date(),
    }
    this.store.set(keyId, { pair, privateKey })
    return pair
  }

  async sign(keyId: string, data: Uint8Array): Promise<SignatureResult> {
    const stored = this.store.get(keyId)
    if (!stored) throw new Error(`Key no encontrada: ${keyId}`)
    const { pair, privateKey } = stored

    let signature: Uint8Array

    switch (pair.algorithm) {
      case "ecdsa-p256": {
        const sig = p256.sign(data, privateKey)
        signature = sig.toCompactRawBytes()
        break
      }
      case "ml-dsa-44":
        signature = ml_dsa44.sign(privateKey, data)
        break
      case "ml-dsa-65":
        signature = ml_dsa65.sign(privateKey, data)
        break
      case "ml-dsa-87":
        signature = ml_dsa87.sign(privateKey, data)
        break
      case "slh-dsa-sha2-128s":
        signature = slh_dsa_sha2_128s.sign(privateKey, data)
        break
      case "hybrid-p256-mldsa65": {
        // Firma con ambos algoritmos — el verificador puede usar cualquiera
        const ecPrivLen = 32
        const ecPriv    = privateKey.slice(0, ecPrivLen)
        const pqPriv    = privateKey.slice(ecPrivLen)
        const ecSig     = p256.sign(data, ecPriv).toCompactRawBytes()
        const pqSig     = ml_dsa65.sign(pqPriv, data)
        // Codificación: [2 bytes length][ec_sig][pq_sig]
        const lenBuf    = new Uint8Array(2)
        new DataView(lenBuf.buffer).setUint16(0, ecSig.length)
        signature = concat(lenBuf, ecSig, pqSig)
        break
      }
      default:
        throw new Error(`Algoritmo no soportado: ${pair.algorithm}`)
    }

    return { signature, algorithm: pair.algorithm, keyId }
  }

  async verify(keyId: string, data: Uint8Array, signature: Uint8Array): Promise<VerifyResult> {
    const stored = this.store.get(keyId)
    if (!stored) throw new Error(`Key no encontrada: ${keyId}`)
    const { pair } = stored
    const pub = pair.publicKey

    let valid: boolean

    switch (pair.algorithm) {
      case "ecdsa-p256":
        valid = p256.verify(signature, data, pub)
        break
      case "ml-dsa-44":
        valid = ml_dsa44.verify(pub, data, signature)
        break
      case "ml-dsa-65":
        valid = ml_dsa65.verify(pub, data, signature)
        break
      case "ml-dsa-87":
        valid = ml_dsa87.verify(pub, data, signature)
        break
      case "slh-dsa-sha2-128s":
        valid = slh_dsa_sha2_128s.verify(pub, data, signature)
        break
      case "hybrid-p256-mldsa65": {
        // Extraer firma ECDSA y PQ por separado
        const ecPubLen = new DataView(pub.buffer, pub.byteOffset).getUint16(0)
        const ecPub    = pub.slice(2, 2 + ecPubLen)
        const pqPub    = pub.slice(2 + ecPubLen)
        const ecSigLen = new DataView(signature.buffer, signature.byteOffset).getUint16(0)
        const ecSig    = signature.slice(2, 2 + ecSigLen)
        const pqSig    = signature.slice(2 + ecSigLen)
        // Ambas firmas deben ser válidas
        valid = p256.verify(ecSig, data, ecPub) && ml_dsa65.verify(pqPub, data, pqSig)
        break
      }
      default:
        throw new Error(`Algoritmo no soportado: ${pair.algorithm}`)
    }

    return { valid, algorithm: pair.algorithm }
  }

  listKeys(): KeyPair[] {
    return [...this.store.values()].map(s => s.pair)
  }

  info(): HSMInfo {
    return {
      manufacturer: "juanchi.dev",
      model: "SoftwareHSM v1.0",
      firmwareVersion: "1.0.0-pqc",
      algorithms: [
        "ecdsa-p256",
        "ml-dsa-44",
        "ml-dsa-65",
        "ml-dsa-87",
        "slh-dsa-sha2-128s",
        "hybrid-p256-mldsa65",
      ],
      fipsMode: false, // software sim — no tiene validación FIPS 140-3
    }
  }
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const a of arrays) { out.set(a, offset); offset += a.length }
  return out
}
