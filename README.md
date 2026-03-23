# BellaBaxter.Crypto

[![NuGet](https://img.shields.io/nuget/v/BellaBaxter.Crypto.svg)](https://www.nuget.org/packages/BellaBaxter.Crypto)

Shared ECIES cryptography primitives used by the **Bella Baxter API** (server-side encrypt) and the **.NET SDK / CLI** (client-side decrypt) to implement end-to-end encrypted secret delivery.

> **⚠️ SDK Wire Contract** — The algorithm constants in this package are frozen across 9 language SDKs (Go, TypeScript, Dart, Java, PHP, Python, Ruby, .NET, Swift). Do not change them without updating every SDK. See [`SDK_CONTRACT.md`](../SDK_CONTRACT.md).

---

## What it does

When a Bella Baxter client sends an `X-E2E-Public-Key` header with its P-256 public key, the API encrypts the secret values before returning them. Only the client holding the matching private key can decrypt them — not even Bella Baxter's own infrastructure can read the plaintext in transit.

```
Client                              Bella Baxter API
──────                              ────────────────
Generate P-256 keypair
  → send X-E2E-Public-Key: <pub>   ─────────────────────►
                                    EciesAlgorithm.Encrypt(secret, clientPub)
                                      1. Generate ephemeral server keypair
                                      2. ECDH(serverPriv, clientPub) → shared secret
                                      3. HKDF-SHA256 → 32-byte AES key
                                      4. AES-256-GCM encrypt → {ciphertext, nonce, tag}
                                      5. Return E2EEncryptedPayload
  ◄─────────────────────────────── { serverPublicKey, nonce, tag, ciphertext }

EciesAlgorithm.Decrypt(payload, clientPrivKey)
  1. ECDH(clientPriv, serverPub) → same shared secret
  2. HKDF → same AES key
  3. AES-256-GCM decrypt → plaintext bytes ✓
```

---

## Algorithm (frozen)

| Parameter | Value |
|-----------|-------|
| Curve | NIST P-256 (secp256r1) |
| Key exchange | ECDH raw secret agreement |
| KDF | HKDF-SHA-256, salt = 32 zero bytes, info = `"bella-e2ee-v1"` |
| Cipher | AES-256-GCM, 12-byte nonce, 16-byte tag |
| Public key format | X.509 SubjectPublicKeyInfo (SPKI) DER, Base64 strict |
| Request header | `X-E2E-Public-Key` (exact casing) |
| Algorithm ID | `ECDH-P256-HKDF-SHA256-AES256GCM` |

The ephemeral server keypair gives **perfect forward secrecy** — each request uses a fresh keypair so compromising one response reveals nothing about others.

---

## API

### `EciesAlgorithm.Encrypt`

Used by the **Bella Baxter API** to encrypt secrets before returning them.

```csharp
E2EEncryptedPayload payload = EciesAlgorithm.Encrypt(
    plaintext: System.Text.Encoding.UTF8.GetBytes(secretJson),
    clientPublicKeyBase64: clientPubKeyFromHeader
);
```

### `EciesAlgorithm.Decrypt`

Used by the **.NET SDK and CLI** to decrypt the response.

```csharp
using var clientKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
// ... load or generate clientKey ...

byte[] plaintext = EciesAlgorithm.Decrypt(payload, clientKey);
string json = System.Text.Encoding.UTF8.GetString(plaintext);
```

Throws `CryptographicException` if the authentication tag doesn't match (tampered data or wrong key).

### `E2EEncryptedPayload`

Wire format returned by secrets endpoints when E2EE is active:

```json
{
  "encrypted": true,
  "algorithm": "ECDH-P256-HKDF-SHA256-AES256GCM",
  "serverPublicKey": "<base64 SPKI>",
  "nonce": "<base64 12 bytes>",
  "tag": "<base64 16 bytes>",
  "ciphertext": "<base64>"
}
```

When E2EE is not requested the API returns `{ "encrypted": false }` with empty string fields — clients should check `Encrypted` before calling `Decrypt`.

---

## Installation

```bash
dotnet add package BellaBaxter.Crypto
```

---

## Security notes

- The raw ECDH secret and derived AES key are **zeroed from memory** immediately after use via `CryptographicOperations.ZeroMemory`.
- The client's private key never leaves the client process.
- The server's ephemeral private key is destroyed after each encrypt call.

---

## Publishing

This package is published to NuGet via a tag-based GitHub Action in this repo:

```bash
git tag v0.1.1
git push origin v0.1.1
```

Requires the `NUGET_API_KEY` secret set on this repository (NuGet.org API key scoped to `BellaBaxter.*`).
