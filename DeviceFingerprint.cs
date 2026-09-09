using System.Security.Cryptography;

namespace BellaBaxter.Crypto;

/// <summary>
/// spec 037 — the ONE fingerprint algorithm for a ZKE device public key, and the ONE validator that
/// decides whether a presented key is acceptable at all.
/// </summary>
/// <remarks>
/// <para><b>Why it lives here.</b> Two binaries print this string: the API (the Devices view, the audit
/// row) and the CLI (<c>bella auth setup</c>, <c>bella auth status</c>). A fingerprint's only job is to
/// be compared by eye, so two formats — the CLI's old truncated colon-hex and the trail's
/// <c>SHA256:base64</c> — make the one job impossible. <c>BellaBaxter.Crypto</c> is referenced by both,
/// so this is the single place either can compute it (plan D5, research R8).</para>
///
/// <para><b>The format is the OpenSSH convention</b> already used by <c>SshAccessLog.KeyFingerprint</c>
/// and <c>SshShared</c>: <c>SHA256:</c> followed by the unpadded base64 of the SHA-256 over the DER
/// SubjectPublicKeyInfo. Over the DER, never over the base64 text — whitespace or padding differences in
/// the transport encoding must not produce a different device.</para>
///
/// <para><b>Public material only.</b> Everything here takes a public key. A fingerprint is a digest of a
/// public key and is not secret; a private key is never accepted (<see cref="TryParseSpki"/> rejects
/// PKCS#8) and never passes through this type.</para>
/// </remarks>
public static class DeviceFingerprint
{
    /// <summary>The prefix every fingerprint carries. Part of the string, not a display decoration.</summary>
    public const string Prefix = "SHA256:";

    /// <summary>
    /// The fingerprint of a DER SubjectPublicKeyInfo: <c>SHA256:&lt;unpadded base64 of SHA-256(der)&gt;</c>.
    /// </summary>
    public static string Compute(ReadOnlySpan<byte> spkiDer)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(spkiDer, hash);
        return Prefix + Convert.ToBase64String(hash).TrimEnd('=');
    }

    /// <summary>
    /// The fingerprint of a base64-encoded DER SubjectPublicKeyInfo, after validating it
    /// (<see cref="TryParseSpki"/>). Returns null when the key is not an acceptable P-256 public key —
    /// a caller must never fingerprint something it has not validated.
    /// </summary>
    public static string? ComputeFromBase64(string? spkiBase64) =>
        TryParseSpki(spkiBase64, out var der) ? Compute(der) : null;

    /// <summary>
    /// Validates a presented key: base64 → DER SubjectPublicKeyInfo → importable as an EC public key →
    /// P-256 (<c>KeySize == 256</c>). This is <c>CreateApiKey</c>'s validator, moved here so the API and
    /// the CLI cannot disagree about what is acceptable.
    /// </summary>
    /// <remarks>
    /// Fails closed and silently: every rejection returns false with no reason, because the only caller
    /// that reports one (registration) answers with a single stable message, and the gate must not turn
    /// a parse outcome into a hint. A PKCS#8 <i>private</i> key fails here — <c>ImportSubjectPublicKeyInfo</c>
    /// will not read one — which is the property that keeps private material out of the registry.
    /// </remarks>
    public static bool TryParseSpki(string? spkiBase64, out byte[] der)
    {
        der = [];

        if (string.IsNullOrWhiteSpace(spkiBase64))
            return false;

        try
        {
            var bytes = Convert.FromBase64String(spkiBase64);
            using var ecdh = ECDiffieHellman.Create();
            ecdh.ImportSubjectPublicKeyInfo(bytes, out _);
            if (ecdh.KeySize != 256)
                return false;

            der = bytes;
            return true;
        }
        catch
        {
            return false;
        }
    }
}
