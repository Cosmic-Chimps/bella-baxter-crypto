# Bella Baxter SDK Wire Contract

> **⚠️ STOP — Read this before changing anything in this file's scope.**
>
> The contracts documented here are implemented in **9 language SDKs**.  
> A silent change here breaks every SDK simultaneously and for every customer using them.

---

## What Is a Wire Contract?

A wire contract is a set of API behaviors that SDK code depends on **at the byte level** — 
field names, types, algorithm constants, header names. Unlike internal APIs, these cannot 
be changed with a simple refactor. Every SDK must be updated, released, and customers must 
upgrade before the old behavior can be removed.

---

## Contracted SDKs

| SDK | Location |
|-----|----------|
| Go | `apps/sdk/go/` |
| TypeScript/JS | `apps/sdk/js/` |
| Dart (+ Flutter) | `apps/sdk/dart/` |
| Java | `apps/sdk/java/` |
| PHP | `apps/sdk/php/` |
| Python | `apps/sdk/python/` |
| Ruby | `apps/sdk/ruby/` |
| .NET (C#) | `apps/sdk/dotnet-sdk/` |
| Swift (iOS/macOS) | `apps/sdk/swift/` |

---

## Contract 1: `getAllEnvironmentSecrets` Endpoint

### Route
```
GET /api/v1/projects/{projectRef}/environments/{envSlug}/secrets
```

### `operationId`
```
getAllEnvironmentSecrets
```

> **Why `operationId` matters:** Several SDKs (Swift, .NET) match by `operationId` 
> to decide whether to apply E2EE decryption. Renaming it disables E2EE silently.

### Response Schema — `AllEnvironmentSecretsResponse`

```json
{
  "environmentSlug": "dev",
  "environmentName": "Development",
  "secrets": {
    "DATABASE_URL": "postgres://...",
    "API_KEY": "abc123"
  },
  "version": 42,
  "lastModified": "2026-01-15T10:30:00Z"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `environmentSlug` | `string` | **FROZEN** |
| `environmentName` | `string` | **FROZEN** |
| `secrets` | `object { [key: string]: string }` | **FROZEN** — flat dict, NOT an array |
| `version` | `int64` | **FROZEN** — used for polling / cache invalidation |
| `lastModified` | `string (ISO 8601 date-time)` | **FROZEN** |

#### Rules
- `secrets` is a **flat key→value object**, never an array of `{key, value}` items.
- Field names are **camelCase** (serialized with `JsonSerializerOptions.Web`).
- All fields are **required** — SDKs do not guard for missing fields.

---

## Contract 2: E2EE Wire Format

End-to-end encryption is opt-in per request via the `X-E2E-Public-Key` header.

### Trigger Header
```
X-E2E-Public-Key: <base64-encoded SPKI DER public key>
```

- Header name: `X-E2E-Public-Key` (exact casing — some HTTP stacks are case-sensitive)
- Value: Base64-strict (no line breaks) encoded **X.509 SubjectPublicKeyInfo DER** for a P-256 key

### Encrypted Response Shape

When the header is present, the server responds with:

```json
{
  "encrypted": true,
  "algorithm": "ECDH-P256-HKDF-SHA256-AES256GCM",
  "serverPublicKey": "<base64 SPKI DER>",
  "nonce": "<base64 12 bytes>",
  "tag": "<base64 16 bytes>",
  "ciphertext": "<base64 N bytes>"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `encrypted` | `bool` | Always `true` when encrypted. **FROZEN** |
| `algorithm` | `string` | Informational only. Not parsed by SDKs. |
| `serverPublicKey` | `string` | Base64 SPKI DER of server's ephemeral P-256 key. **FROZEN** |
| `nonce` | `string` | Base64, 12 bytes. **FROZEN** |
| `tag` | `string` | Base64, 16 bytes, separate from ciphertext. **FROZEN** |
| `ciphertext` | `string` | Base64, AES-256-GCM ciphertext. **FROZEN** |

### Crypto Algorithm (ALL values FROZEN)

```
1. Client → Server:  X-E2E-Public-Key: base64(SPKI-DER of client P-256 public key)
2. Server generates: ephemeral P-256 key pair per request
3. ECDH:             sharedSecret = ECDH(serverPrivate, clientPublic)
                     → x-coordinate of the resulting EC point (raw bytes)
4. HKDF-SHA-256:     key = HKDF(
                         IKM  = sharedSecret,
                         salt = 0x00 × 32,          ← 32 zero bytes
                         info = "bella-e2ee-v1",    ← UTF-8, no null terminator
                         L    = 32                  ← 32-byte output
                     )
5. AES-256-GCM:      ciphertext, tag = AES-GCM-Encrypt(
                         key   = key (32 bytes),
                         nonce = random 12 bytes,
                         AAD   = "" (empty),
                         plaintext = JSON of AllEnvironmentSecretsResponse
                     )
```

### What Is Encrypted

The **entire `AllEnvironmentSecretsResponse` JSON** is encrypted — not just the secrets dict.

```
plaintext = JSON.serialize(AllEnvironmentSecretsResponse, camelCase)
         = '{"environmentSlug":"dev","environmentName":"Dev","secrets":{...},"version":42,"lastModified":"..."}'
```

> **Why this matters:** SDKs that decrypt must parse the full response object, not just 
> extract a `secrets` sub-key. All 9 SDKs were updated to handle this in March 2026.

### Which Endpoints Support E2EE

| Endpoint | Supports E2EE |
|----------|--------------|
| `GET .../secrets` (`getAllEnvironmentSecrets`) | ✅ Yes — **full response** encrypted |
| `GET .../providers/{slug}/secrets` (`listSecrets`) | ✅ Yes — secrets array encrypted |
| `GET .../secrets/version` | ❌ No |
| `GET .../secrets/export` | ❌ No |

---

## Change Rules

### ✅ Backward-Compatible (safe to do)
- Adding **new optional fields** to `AllEnvironmentSecretsResponse`
- Adding new endpoints that don't affect existing ones
- Adding new query parameters with defaults

### ❌ Breaking Changes (requires updating ALL 9 SDKs + coordinated release)
- Renaming any field in `AllEnvironmentSecretsResponse`
- Changing `secrets` from a flat dict to an array or nested object
- Changing the `operationId` from `getAllEnvironmentSecrets`
- Changing the route path
- Changing any E2EE crypto constant (curve, KDF params, cipher, HKDF info string)
- Changing the header name `X-E2E-Public-Key`
- Changing any field name in the encrypted payload (`serverPublicKey`, `nonce`, `tag`, `ciphertext`)
- Changing what is encrypted (e.g. encrypting only the secrets dict instead of the full response)

### Process for Breaking Changes
1. Open a discussion issue tagged `sdk-contract-break`
2. Implement changes in server **behind a feature flag or new API version**
3. Update all 9 SDKs
4. Release SDKs
5. Announce migration period
6. Remove old behavior

---

## Server-Side References

| File | Why It's Here |
|------|---------------|
| `BellaBaxter.Crypto/EciesAlgorithm.cs` | The one true implementation of the crypto algorithm |
| `BellaBaxter.Api/Features/…/Secrets/GetAllEnvironmentSecrets.cs` | The contracted endpoint + `AllEnvironmentSecretsResponse` record |
| `BellaBaxter.Api/Infrastructure/Security/E2E/` | E2EE service wiring |
| `BellaBaxter.WebApp/openapi.json` | OpenAPI spec — `x-sdk-contract: frozen` marks contracted operations/schemas |

---

## SDK-Side References

Each SDK has its own E2EE implementation. The key file per SDK:

| SDK | E2EE file | Middleware/Interceptor |
|-----|-----------|----------------------|
| Go | `bellabaxter/client.go` | Kiota `ClientMiddleware` |
| TypeScript | `src/e2ee.ts` | `E2EInterceptor` |
| Dart | `lib/src/e2ee.dart` | `BellaE2eeInterceptor` (Dio) |
| Java | `src/…/E2EEncryption.java` | `E2EEncryptionInterceptor` (OkHttp) |
| PHP | `src/E2EEncryption.php` | `E2EGuzzleMiddleware` |
| Python | `src/bella_baxter/e2ee.py` | `E2EETransport` (httpx) |
| Ruby | `lib/bella_baxter/e2ee.rb` | `E2EEFaradayMiddleware` |
| .NET | `src/E2EEncryptionHandler.cs` | `DelegatingHandler` |
| Swift | `Sources/…/E2EEncryptionMiddleware.swift` | `ClientMiddleware` |

---

*Last updated: March 2026 — all 9 SDKs verified against the format described here.*
