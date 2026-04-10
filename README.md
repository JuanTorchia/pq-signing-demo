# pq-signing-demo

Demo real de firma digital post-quantum usando **ML-DSA** (FIPS 204) y **SLH-DSA** (FIPS 205), con una abstracción tipo HSM que nunca expone las claves privadas.

Proyecto companion del post: [NIST Post-Quantum: cómo migrar tu firma digital y tu HSM](https://juanchi.dev/blog/nist-post-quantum-firma-digital-hsm-migracion)

## Algoritmos implementados

| Algoritmo | Estándar | Firma | PubKey | Quantum-safe |
|-----------|----------|-------|--------|--------------|
| ECDSA P-256 | — | 64 B | 33 B | ❌ |
| ML-DSA-44 | FIPS 204 | 2420 B | 1312 B | ✅ |
| ML-DSA-65 | FIPS 204 | 3309 B | 1952 B | ✅ |
| ML-DSA-87 | FIPS 204 | 4627 B | 2592 B | ✅ |
| SLH-DSA-SHA2-128s | FIPS 205 | 7856 B | 32 B | ✅ |
| Híbrido P-256 + ML-DSA-65 | — | 3373 B | 1987 B | ✅ (transición) |

## Instalación

```bash
npm install
```

## Comandos

```bash
npm run demo       # Demo interactivo: HSM info, firma de docs, JWT, comparativa
npm run benchmark  # Benchmark de tamaños y tiempos (20 iteraciones por algoritmo)
npm run typecheck  # TypeScript type checking
```

## Estructura

```
src/
├── hsm/
│   ├── types.ts          # Interfaz HSMProvider (crypto-agility)
│   └── software-hsm.ts   # Implementación en memoria — claves privadas nunca expuestas
├── demos/
│   ├── sign-document.ts  # Firma de documentos con SHA-256 + tamper detection
│   ├── sign-jwt.ts       # JWT post-quantum con ML-DSA-65 (draft IETF)
│   └── benchmark.ts      # Benchmark visual con bar charts
└── run.ts                # Runner interactivo
```

## Diseño: crypto-agility

```typescript
interface HSMProvider {
  generateKeyPair(algorithm: Algorithm, label: string): Promise<KeyPair>
  sign(keyId: string, data: Uint8Array): Promise<SignatureResult>
  verify(keyId: string, data: Uint8Array, signature: Uint8Array): Promise<VerifyResult>
  listKeys(): KeyPair[]
  info(): HSMInfo
}
```

Para migrar a un HSM real (Utimaco, Thales, AWS CloudHSM): implementá `HSMProvider` usando el driver PKCS#11 del vendor. El resto del código no cambia.

## Librerías

- [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) — ML-DSA y SLH-DSA puro TypeScript
- [`@noble/curves`](https://github.com/paulmillr/noble-curves) — ECDSA P-256
- [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) — SHA-256

Cero dependencias nativas. Cero WASM. TypeScript puro.

## Por qué ML-DSA y no RSA-4096

RSA-4096 y ECDSA P-256 van a ser quebrados por el algoritmo de Shor en una computadora cuántica suficientemente grande. No sabemos cuándo — probablemente no antes de 2030. Pero el ataque "harvest now, decrypt later" ya está ocurriendo: alguien está guardando tus mensajes cifrados hoy para descifrarlos cuando tenga la capacidad.

NIST publicó los estándares finales en 2024:
- **FIPS 203** — ML-KEM (Key Encapsulation, reemplaza Diffie-Hellman)
- **FIPS 204** — ML-DSA (firma digital, reemplaza ECDSA/RSA)
- **FIPS 205** — SLH-DSA (firma stateless, respaldo conservador)

El deadline para agencias federales US es **2035**. Si tu sistema maneja datos con valor de más de 10 años, tenés que empezar ahora.
