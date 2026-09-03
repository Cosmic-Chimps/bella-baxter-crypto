using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace BellaBaxter.Crypto.Certificates;

// spec 020 (T009) — mechanical PEM reading for certificate bundles. No judgement here:
// splitting blocks, loading a key, and reporting what was found. All the "is this
// acceptable?" decisions live in CertificateBundleValidator so there is exactly one
// fail-closed gate (Constitution I).

/// <summary>Reads the parts of a certificate bundle out of PEM text.</summary>
public static partial class CertificateBundleReader
{
    /// <summary>Certificate blocks in the order they appear. The leaf is expected first.</summary>
    public static IReadOnlyList<string> SplitCertificateBlocks(string pem) =>
        string.IsNullOrWhiteSpace(pem)
            ? []
            : CertificateBlockRegex().Matches(pem).Select(m => m.Value).ToList();

    /// <summary>The first private-key block in a PEM, or null when there is none.</summary>
    public static string? ExtractPrivateKeyBlock(string pem)
    {
        if (string.IsNullOrWhiteSpace(pem))
        {
            return null;
        }

        var match = PrivateKeyBlockRegex().Match(pem);
        return match.Success ? match.Value : null;
    }

    /// <summary>
    /// True when the key material is password-protected. Covers both PKCS#8
    /// (<c>ENCRYPTED PRIVATE KEY</c>) and the legacy OpenSSL header form, which .NET cannot
    /// import at all — either way the caller must refuse rather than store it.
    /// </summary>
    public static bool IsEncryptedPrivateKey(string keyPem) =>
        !string.IsNullOrWhiteSpace(keyPem)
        && (
            keyPem.Contains("ENCRYPTED PRIVATE KEY", StringComparison.Ordinal)
            || keyPem.Contains("Proc-Type: 4,ENCRYPTED", StringComparison.Ordinal)
            || keyPem.Contains("DEK-Info:", StringComparison.Ordinal)
        );

    /// <summary>
    /// Loads an UNENCRYPTED private key. Returns null when the key cannot be parsed; the
    /// caller distinguishes "encrypted" from "unreadable" via
    /// <see cref="IsEncryptedPrivateKey"/> so the operator gets an accurate reason.
    /// </summary>
    public static AsymmetricAlgorithm? TryLoadPrivateKey(string keyPem)
    {
        if (string.IsNullOrWhiteSpace(keyPem) || IsEncryptedPrivateKey(keyPem))
        {
            return null;
        }

        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(keyPem);
            return rsa;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            rsa.Dispose();
        }

        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromPem(keyPem);
            return ecdsa;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            ecdsa.Dispose();
            return null;
        }
    }

    /// <summary>
    /// Returns the chain without a trailing self-signed root, or the chain unchanged when it
    /// does not end in one. Some appliances refuse an uploaded chain containing a root.
    /// </summary>
    public static string StripSelfSignedRoot(string chainPem)
    {
        var blocks = SplitCertificateBlocks(chainPem);
        if (blocks.Count < 2)
        {
            return chainPem;
        }

        using var last = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(
            blocks[^1]
        );
        var isSelfSigned = last.SubjectName.RawData.AsSpan()
            .SequenceEqual(last.IssuerName.RawData);

        return isSelfSigned ? string.Join('\n', blocks.Take(blocks.Count - 1)) : chainPem;
    }

    [GeneratedRegex(
        "-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        RegexOptions.Singleline
    )]
    private static partial Regex CertificateBlockRegex();

    [GeneratedRegex(
        "-----BEGIN (?:ENCRYPTED )?(?:RSA |EC )?PRIVATE KEY-----.*?-----END (?:ENCRYPTED )?(?:RSA |EC )?PRIVATE KEY-----",
        RegexOptions.Singleline
    )]
    private static partial Regex PrivateKeyBlockRegex();
}
