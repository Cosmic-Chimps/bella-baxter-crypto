using System.Security.Cryptography;

namespace BellaBaxter.Crypto;

// ╔══════════════════════════════════════════════════════════════════════════════════╗
// ║  ⚠️  SDK CONTRACT — DO NOT CHANGE WITHOUT UPDATING ALL SDKs  ⚠️               ║
// ║                                                                                  ║
// ║  This algorithm is a CROSS-SDK WIRE CONTRACT shared by 9 language SDKs:         ║
// ║    Go · TypeScript · Dart · Java · PHP · Python · Ruby · .NET · Swift           ║
// ║                                                                                  ║
// ║  FROZEN values — any change SILENTLY BREAKS every SDK:                          ║
// ║    • Curve:       NIST P-256 (secp256r1)                                        ║
// ║    • KDF:         HKDF-SHA-256, salt = 32 zero bytes, info = "bella-e2ee-v1"   ║
// ║    • Cipher:      AES-256-GCM, 12-byte nonce, 16-byte tag (separate field)      ║
// ║    • Public key:  X.509 SubjectPublicKeyInfo DER, Base64 strict                 ║
// ║    • Header:      X-E2E-Public-Key (exact casing)                               ║
// ║    • Payload:     { encrypted, serverPublicKey, nonce, tag, ciphertext }        ║
// ║                                                                                  ║
// ║  See: apps/sdk/SDK_CONTRACT.md for the full specification.                      ║
// ╚══════════════════════════════════════════════════════════════════════════════════╝

/// <summary>
/// ECIES primitives: ECDH-P256 + HKDF-SHA256 + AES-256-GCM.
///
/// Both the API (encrypt) and all SDKs/CLI (decrypt) use these methods — guaranteeing
/// the algorithm is always in sync on both sides.
///
/// Per-request flow (encrypt):
///   1. Generate ephemeral server P-256 keypair (perfect forward secrecy).
///   2. Import client SPKI public key.
///   3. ECDH → raw shared secret (32 bytes).
///   4. HKDF-SHA256(salt=null → 32-zero-bytes, info="bella-e2ee-v1") → 32-byte AES key.
///   5. AES-256-GCM encrypt with random 12-byte nonce → ciphertext + 16-byte tag.
///   6. Return payload with server public key so client can reproduce the shared secret.
///
/// Decrypt is the mirror image:
///   1. Import server ephemeral public key.
///   2. ECDH(clientPrivKey, serverPubKey) → same shared secret.
///   3. HKDF → same AES key.
///   4. AES-256-GCM decrypt → plaintext bytes.
/// </summary>
public static class EciesAlgorithm
{
    /// <summary>Algorithm identifier embedded in every payload.</summary>
    public const string AlgorithmId = "ECDH-P256-HKDF-SHA256-AES256GCM";

    private static readonly byte[] HkdfInfo = "bella-e2ee-v1"u8.ToArray();
    private const int NonceSize = 12; // AES-GCM standard nonce
    private const int TagSize = 16; // AES-GCM authentication tag

    // ---------------------------------------------------------------------------
    // Encrypt — called by the API (server side)
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> for the client identified by
    /// <paramref name="clientPublicKeyBase64"/> (base64-encoded SPKI, P-256).
    /// </summary>
    public static E2EEncryptedPayload Encrypt(
        ReadOnlySpan<byte> plaintext,
        string clientPublicKeyBase64
    )
    {
        var clientPubBytes = Convert.FromBase64String(clientPublicKeyBase64);

        using var serverEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var clientEcdh = ECDiffieHellman.Create();
        clientEcdh.ImportSubjectPublicKeyInfo(clientPubBytes, out _);

        var rawSecret = serverEcdh.DeriveRawSecretAgreement(clientEcdh.PublicKey);
        var aesKey = DeriveAesKey(rawSecret);

        var nonce = new byte[NonceSize];
        var tag = new byte[TagSize];
        var ciphertext = new byte[plaintext.Length];
        RandomNumberGenerator.Fill(nonce);

        using var aesGcm = new AesGcm(aesKey, TagSize);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

        var serverPubBytes = serverEcdh.ExportSubjectPublicKeyInfo();

        CryptographicOperations.ZeroMemory(aesKey);
        CryptographicOperations.ZeroMemory(rawSecret);

        return new E2EEncryptedPayload(
            Encrypted: true,
            Algorithm: AlgorithmId,
            ServerPublicKey: Convert.ToBase64String(serverPubBytes),
            Nonce: Convert.ToBase64String(nonce),
            Tag: Convert.ToBase64String(tag),
            Ciphertext: Convert.ToBase64String(ciphertext)
        );
    }

    // ---------------------------------------------------------------------------
    // Decrypt — called by all SDKs and CLI (client side)
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Decrypts an <see cref="E2EEncryptedPayload"/> using the client's private key.
    /// Returns the raw plaintext bytes — callers deserialize to their own model.
    /// Throws <see cref="CryptographicException"/> if the tag or key is wrong.
    /// </summary>
    public static byte[] Decrypt(E2EEncryptedPayload payload, ECDiffieHellman clientKey)
    {
        var serverPubBytes = Convert.FromBase64String(payload.ServerPublicKey);
        var nonce = Convert.FromBase64String(payload.Nonce);
        var tag = Convert.FromBase64String(payload.Tag);
        var ciphertext = Convert.FromBase64String(payload.Ciphertext);

        using var serverEcdh = ECDiffieHellman.Create();
        serverEcdh.ImportSubjectPublicKeyInfo(serverPubBytes, out _);

        var rawSecret = clientKey.DeriveRawSecretAgreement(serverEcdh.PublicKey);
        var aesKey = DeriveAesKey(rawSecret);

        try
        {
            using var aesGcm = new AesGcm(aesKey, TagSize);
            var plaintext = new byte[ciphertext.Length];
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
            CryptographicOperations.ZeroMemory(rawSecret);
        }
    }

    // ---------------------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------------------

    private static byte[] DeriveAesKey(byte[] rawSecret) =>
        HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: rawSecret,
            outputLength: 32,
            salt: (byte[]?)null, // RFC 5869 §2.2: null → HashLen zero bytes
            info: HkdfInfo
        );
}
