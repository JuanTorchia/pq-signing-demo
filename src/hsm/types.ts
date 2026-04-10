/**
 * Interfaz del Software HSM.
 *
 * Está diseñada para ser un espejo del contrato que va a exponer
 * PKCS#11 v3.x cuando los vendors actualicen el firmware a PQC.
 * Cuando tengas un HSM real con ML-DSA, reemplazás SoftwareHSM
 * por una implementación que habla PKCS#11 — el resto del código
 * no cambia.
 */

export type Algorithm =
  | "ecdsa-p256"       // ECDSA con P-256 — clásico, va a ser deprecado en 2035
  | "ml-dsa-44"        // ML-DSA nivel 2 (~128 bits de seguridad cuántica)
  | "ml-dsa-65"        // ML-DSA nivel 3 (~192 bits) — recomendado para la mayoría
  | "ml-dsa-87"        // ML-DSA nivel 5 (~256 bits) — máxima seguridad
  | "slh-dsa-sha2-128s" // SLH-DSA conservador — solo hash, sin supuestos algebraicos
  | "hybrid-p256-mldsa65" // Transición: firma con ambos simultáneamente

export interface KeyPair {
  keyId: string         // Handle opaco — como el CKA_ID en PKCS#11
  algorithm: Algorithm
  publicKey: Uint8Array // La pública sí sale del HSM
  createdAt: Date
}

export interface SignatureResult {
  signature: Uint8Array
  algorithm: Algorithm
  keyId: string
}

export interface VerifyResult {
  valid: boolean
  algorithm: Algorithm
}

/**
 * Interfaz del HSM — espejo del PKCS#11 Session interface.
 * La clave privada NUNCA sale del HSM.
 */
export interface HSMProvider {
  /** Genera un par de claves y las almacena internamente (CKM_ML_DSA_KEY_PAIR_GEN) */
  generateKeyPair(algorithm: Algorithm, label: string): Promise<KeyPair>

  /** Firma datos usando la clave interna referenciada por keyId (C_Sign) */
  sign(keyId: string, data: Uint8Array): Promise<SignatureResult>

  /** Verifica una firma (C_Verify) */
  verify(keyId: string, data: Uint8Array, signature: Uint8Array): Promise<VerifyResult>

  /** Lista los keys disponibles (C_FindObjects) */
  listKeys(): KeyPair[]

  /** Info sobre el HSM (C_GetInfo) */
  info(): HSMInfo
}

export interface HSMInfo {
  manufacturer: string
  model: string
  firmwareVersion: string
  algorithms: Algorithm[]
  fipsMode: boolean
}
