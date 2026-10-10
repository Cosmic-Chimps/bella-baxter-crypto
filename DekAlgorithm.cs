using System.Security.Cryptography;
using System.Text;

namespace BellaBaxter.Crypto;

// ╔══════════════════════════════════════════════════════════════════════════════╗
// ║  DEK (Data Encryption Key) — AES-256-GCM at-rest encryption                ║
// ║  Used to encrypt secret values before storing in external providers.        ║
// ║                                                                              ║
// ║  Wire format: "bellabaxter:v1:{base64(12-byte nonce|16-byte tag|ciphertext)}"║
// ║                                                                              ║
// ║  The DEK itself (32 raw bytes) is distributed wrapped with ECIES:           ║
// ║    EciesAlgorithm.Encrypt(dek, masterPublicKey) → E2EEncryptedPayload       ║
// ║  CLI/SDK decrypts the wrapped DEK using EciesAlgorithm.Decrypt().           ║
// ╚══════════════════════════════════════════════════════════════════════════════╝
public static class DekAlgorithm
{
    public const string Prefix = "bellabaxter:v1:";

    /// <summary>
    /// spec 077 — the bound envelope: the same byte layout as <see cref="Prefix"/>, sealed under a key
    /// derived for the value's environment (or its project's shared scope) with its
    /// <see cref="SecretBinding"/> as associated data. A ciphertext read anywhere else fails to open.
    /// </summary>
    public const string PrefixV2 = "bellabaxter:v2:";
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int DekSize = 32; // AES-256

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with the given 32-byte DEK using AES-256-GCM.
    /// Returns a self-contained string in the format "bellabaxter:v1:{base64}".
    /// </summary>
    public static string Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> dek)
        => Seal(Prefix, plaintext, dek, ReadOnlySpan<byte>.Empty);

    /// <summary>
    /// spec 077 — seals <paramref name="plaintext"/> as <c>bellabaxter:v2:</c> under
    /// <paramref name="derivedKey"/> (<see cref="DataKeyDerivation"/>), binding it to <paramref name="binding"/>.
    /// </summary>
    public static string EncryptBound(string plaintext, ReadOnlySpan<byte> derivedKey, SecretBinding binding)
        => Seal(PrefixV2, Encoding.UTF8.GetBytes(plaintext), derivedKey, binding.ToAssociatedData());

    /// <summary>
    /// spec 077 — opens a <c>bellabaxter:v2:</c> value with <paramref name="derivedKey"/>, only when it
    /// was sealed for <paramref name="binding"/>.
    /// </summary>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// Wrong key, or the value belongs somewhere else.
    /// </exception>
    public static string DecryptBound(string envelope, ReadOnlySpan<byte> derivedKey, SecretBinding binding)
        => Encoding.UTF8.GetString(Open(PrefixV2, envelope, derivedKey, binding.ToAssociatedData()));

    private static string Seal(string prefix, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> dek, ReadOnlySpan<byte> associatedData)
    {
        if (dek.Length != DekSize)
            throw new ArgumentException($"DEK must be {DekSize} bytes (AES-256).", nameof(dek));

        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var tag = new byte[TagSize];
        var ciphertext = new byte[plaintext.Length];

        // The span overload, NOT dek.ToArray() (#829): the copy that made was a second live
        // 32-byte DEK on the heap that no caller could reach, so the fifteen call sites that
        // dutifully zero their own `dek` were zeroing one of two copies. AesGcm keeps its own
        // internal schedule either way and Dispose clears it; the avoidable copy was ours.
        using var aesGcm = new AesGcm(dek, TagSize);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        // Pack: nonce (12) | tag (16) | ciphertext (N)
        var combined = new byte[NonceSize + TagSize + ciphertext.Length];
        nonce.CopyTo(combined, 0);
        tag.CopyTo(combined, NonceSize);
        ciphertext.CopyTo(combined, NonceSize + TagSize);

        return prefix + Convert.ToBase64String(combined);
    }

    /// <summary>
    /// Encrypts a UTF-8 string value.
    /// </summary>
    public static string Encrypt(string plaintext, ReadOnlySpan<byte> dek)
        => Encrypt(Encoding.UTF8.GetBytes(plaintext), dek);

    /// <summary>
    /// Decrypts a "bellabaxter:v1:{base64}" string using the given 32-byte DEK.
    /// Returns the decrypted bytes.
    /// </summary>
    public static byte[] Decrypt(string encrypted, ReadOnlySpan<byte> dek)
        => Open(Prefix, encrypted, dek, ReadOnlySpan<byte>.Empty);

    private static byte[] Open(string prefix, string encrypted, ReadOnlySpan<byte> dek, ReadOnlySpan<byte> associatedData)
    {
        if (!encrypted.StartsWith(prefix, StringComparison.Ordinal))
            throw new ArgumentException($"Value does not start with expected prefix '{prefix}'.", nameof(encrypted));

        if (dek.Length != DekSize)
            throw new ArgumentException($"DEK must be {DekSize} bytes (AES-256).", nameof(dek));

        var combined = Convert.FromBase64String(encrypted[prefix.Length..]);

        if (combined.Length < NonceSize + TagSize)
            throw new ArgumentException("Encrypted payload is too short.", nameof(encrypted));

        var nonce = combined[..NonceSize];
        var tag = combined[NonceSize..(NonceSize + TagSize)];
        var ciphertext = combined[(NonceSize + TagSize)..];

        var plaintext = new byte[ciphertext.Length];

        using var aesGcm = new AesGcm(dek, TagSize);
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);

        return plaintext;
    }

    /// <summary>
    /// Decrypts a "bellabaxter:v1:{base64}" string to a UTF-8 string value.
    /// </summary>
    public static string DecryptToString(string encrypted, ReadOnlySpan<byte> dek)
        => Encoding.UTF8.GetString(Decrypt(encrypted, dek));

    /// <summary>
    /// Returns true if the value is encrypted with the Bella at-rest scheme.
    /// Secret values starting with "bellabaxter:" are reserved and cannot be
    /// created by users — write endpoints reject such values with 400.
    /// </summary>
    public static bool IsEncrypted(string value)
        => value.StartsWith(Prefix, StringComparison.Ordinal) || IsBound(value);

    /// <summary>spec 077 — whether the value is in the bound <c>bellabaxter:v2:</c> envelope.</summary>
    public static bool IsBound(string value)
        => value.StartsWith(PrefixV2, StringComparison.Ordinal);

    /// <summary>
    /// Returns true if the value uses the Bella reserved prefix (any version).
    /// Used for write-side validation: values starting with "bellabaxter:" are rejected.
    /// </summary>
    public static bool HasReservedPrefix(string value)
        => value.StartsWith("bellabaxter:", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Generates a new cryptographically random 32-byte DEK.
    /// The caller is responsible for zeroing the returned array after use
    /// via <see cref="CryptographicOperations.ZeroMemory"/>.
    /// </summary>
    public static byte[] GenerateDek()
    {
        var dek = new byte[DekSize];
        RandomNumberGenerator.Fill(dek);
        return dek;
    }
}
