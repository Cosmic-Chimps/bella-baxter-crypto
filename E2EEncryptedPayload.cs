namespace BellaBaxter.Crypto;

/// <summary>
/// Wire format returned by secrets endpoints when the client requests E2EE
/// (i.e., when the X-E2E-Public-Key header is present).
/// </summary>
public sealed record E2EEncryptedPayload(
    bool Encrypted,
    string Algorithm,
    string ServerPublicKey, // base64-encoded SPKI — client needs this for ECDH
    string Nonce, // base64-encoded 12-byte AES-GCM nonce
    string Tag, // base64-encoded 16-byte AES-GCM authentication tag
    string Ciphertext // base64-encoded encrypted payload
);
