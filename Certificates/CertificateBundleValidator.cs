using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace BellaBaxter.Crypto.Certificates;

// spec 020 (T010, T011) — the single fail-closed gate for certificate bundles.
//
// Called by BOTH the CLI import (before any write) and the API write path (before any event),
// so the two can never disagree about what is acceptable. Every check REJECTS on failure;
// nothing here falls back to a weaker path, and no exception is swallowed into acceptance
// (Constitution I — Security by Default, Fail Closed).
//
// Check order is deliberate: the chain is established before the key, and identity before
// validity, so the operator gets the FIRST thing that is actually wrong rather than a
// downstream symptom of it.

/// <summary>Validates a certificate bundle and derives its facts.</summary>
public static class CertificateBundleValidator
{
    private const string SubjectAlternativeNameOid = "2.5.29.17";

    /// <summary>
    /// Validate a PEM chain plus its PEM private key. Returns the derived facts on success, or
    /// a typed rejection with an operator-readable reason.
    /// </summary>
    /// <param name="now">Clock for the validity check; defaults to UTC now.</param>
    public static CertificateBundleValidation Validate(
        string chainPem,
        string privateKeyPem,
        DateTimeOffset? now = null
    )
    {
        var at = now ?? DateTimeOffset.UtcNow;

        var blocks = CertificateBundleReader.SplitCertificateBlocks(chainPem);
        if (blocks.Count == 0)
        {
            return CertificateBundleValidation.Rejected(
                CertificateBundleRejection.UnreadableChain,
                "no certificate could be read from the chain."
            );
        }

        var certificates = new List<X509Certificate2>(blocks.Count);
        try
        {
            foreach (var block in blocks)
            {
                try
                {
                    certificates.Add(X509Certificate2.CreateFromPem(block));
                }
                catch (Exception ex) when (ex is CryptographicException or ArgumentException)
                {
                    return CertificateBundleValidation.Rejected(
                        CertificateBundleRejection.UnreadableChain,
                        $"certificate block {certificates.Count + 1} could not be parsed."
                    );
                }
            }

            var leaf = certificates[0];

            if (certificates.Count > 1 && IsSelfSigned(leaf))
            {
                return CertificateBundleValidation.Rejected(
                    CertificateBundleRejection.ChainNotLeafFirst,
                    "the first certificate is self-signed, so the chain is not leaf-first "
                        + "(the leaf must come first)."
                );
            }

            if (certificates.Count > 1 && Issued(leaf, certificates[1]))
            {
                return CertificateBundleValidation.Rejected(
                    CertificateBundleRejection.ChainNotLeafFirst,
                    "the first certificate issued the second, so the chain is reversed "
                        + "(the leaf must come first)."
                );
            }

            for (var i = 0; i < certificates.Count - 1; i++)
            {
                if (!Issued(certificates[i + 1], certificates[i]))
                {
                    return CertificateBundleValidation.Rejected(
                        CertificateBundleRejection.BrokenChainOrder,
                        $"certificate {i + 1} is not issued by certificate {i + 2}; "
                            + "the chain does not link."
                    );
                }
            }

            // Names lining up is NOT proof the chain links: two different CAs can carry the
            // same distinguished name. Verify the signatures cryptographically, or a chain
            // assembled from unrelated certificates would be accepted (Constitution I).
            if (!ChainLinksCryptographically(certificates, out var linkError))
            {
                return CertificateBundleValidation.Rejected(
                    CertificateBundleRejection.BrokenChainOrder,
                    $"the chain does not verify: {linkError}"
                );
            }

            if (CertificateBundleReader.IsEncryptedPrivateKey(privateKeyPem))
            {
                return CertificateBundleValidation.Rejected(
                    CertificateBundleRejection.EncryptedKey,
                    "the private key is encrypted; this path requires an unencrypted key."
                );
            }

            using var privateKey = CertificateBundleReader.TryLoadPrivateKey(privateKeyPem);
            if (privateKey is null)
            {
                return CertificateBundleValidation.Rejected(
                    CertificateBundleRejection.UnreadableKey,
                    "the private key could not be read as an unencrypted RSA or EC key."
                );
            }

            if (!KeyMatchesCertificate(privateKey, leaf))
            {
                return CertificateBundleValidation.Rejected(
                    CertificateBundleRejection.KeyDoesNotMatchCertificate,
                    "the private key does not belong to the leaf certificate."
                );
            }

            var commonName = leaf.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            if (string.IsNullOrWhiteSpace(commonName))
            {
                return CertificateBundleValidation.Rejected(
                    CertificateBundleRejection.MissingCommonName,
                    "the leaf certificate carries no readable common name."
                );
            }

            var notBefore = new DateTimeOffset(leaf.NotBefore.ToUniversalTime());
            var notAfter = new DateTimeOffset(leaf.NotAfter.ToUniversalTime());
            if (at < notBefore)
            {
                return CertificateBundleValidation.Rejected(
                    CertificateBundleRejection.OutsideValidityWindow,
                    $"the certificate is not valid until {notBefore:yyyy-MM-dd}."
                );
            }

            if (at > notAfter)
            {
                return CertificateBundleValidation.Rejected(
                    CertificateBundleRejection.OutsideValidityWindow,
                    $"the certificate expired on {notAfter:yyyy-MM-dd}."
                );
            }

            var (algorithm, keySize) = DescribePublicKey(leaf);

            return CertificateBundleValidation.Valid(
                new CertificateFacts(
                    CommonName: commonName,
                    SubjectAlternativeNames: ReadDnsNames(leaf),
                    Issuer: leaf.Issuer,
                    NotBefore: notBefore,
                    NotAfter: notAfter,
                    KeyAlgorithm: algorithm,
                    KeySizeBits: keySize,
                    Sha256Fingerprint: Convert
                        .ToHexString(leaf.GetCertHash(HashAlgorithmName.SHA256))
                        .ToLowerInvariant(),
                    ChainLength: certificates.Count,
                    ChainIncludesSelfSignedRoot: certificates.Count > 1
                        && IsSelfSigned(certificates[^1])
                )
            );
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    private static bool IsSelfSigned(X509Certificate2 certificate) =>
        certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);

    /// <summary>True when <paramref name="issuer"/> is named as the issuer of <paramref name="subject"/>.</summary>
    private static bool Issued(X509Certificate2 issuer, X509Certificate2 subject) =>
        issuer.SubjectName.RawData.AsSpan().SequenceEqual(subject.IssuerName.RawData);

    /// <summary>
    /// Verifies each certificate is really signed by the one after it.
    /// </summary>
    /// <remarks>
    /// Deliberately NOT <see cref="X509Chain"/>: the question here is internal linkage, not
    /// trust. A chain policy would drag in platform trust stores, revocation lookups, and a
    /// requirement that the anchor be self-signed — which a legitimately root-less
    /// leaf-plus-intermediate chain does not satisfy. Verifying signatures pairwise answers
    /// exactly the question asked, with no network and no ambient trust.
    /// </remarks>
    private static bool ChainLinksCryptographically(
        List<X509Certificate2> certificates,
        out string? error
    )
    {
        for (var i = 0; i < certificates.Count - 1; i++)
        {
            if (!IsSignedBy(certificates[i], certificates[i + 1], out var pairError))
            {
                error = $"certificate {i + 1} is not signed by certificate {i + 2} ({pairError})";
                return false;
            }
        }

        error = null;
        return true;
    }

    /// <summary>Verifies <paramref name="child"/>'s signature against <paramref name="issuer"/>'s public key.</summary>
    private static bool IsSignedBy(
        X509Certificate2 child,
        X509Certificate2 issuer,
        out string error
    )
    {
        byte[] tbs;
        string signatureAlgorithmOid;
        byte[] signature;
        try
        {
            // RFC 5280: Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
            var certificate = new System.Formats.Asn1.AsnReader(
                child.RawData,
                System.Formats.Asn1.AsnEncodingRules.DER
            ).ReadSequence();
            tbs = certificate.ReadEncodedValue().ToArray();
            signatureAlgorithmOid = certificate.ReadSequence().ReadObjectIdentifier();
            signature = certificate.ReadBitString(out _);
        }
        catch (System.Formats.Asn1.AsnContentException)
        {
            error = "its structure could not be read";
            return false;
        }

        if (!SignatureAlgorithms.TryGetValue(signatureAlgorithmOid, out var algorithm))
        {
            // Fail closed on an algorithm we cannot verify, and name it so the gap is
            // actionable rather than mysterious.
            error = $"unsupported signature algorithm {signatureAlgorithmOid}";
            return false;
        }

        try
        {
            if (algorithm.IsEcdsa)
            {
                using var ecdsa = issuer.GetECDsaPublicKey();
                if (ecdsa is null)
                {
                    error = "the issuer has no EC public key";
                    return false;
                }

                var verified = ecdsa.VerifyData(
                    tbs,
                    signature,
                    algorithm.Hash,
                    DSASignatureFormat.Rfc3279DerSequence
                );
                error = verified ? string.Empty : "the signature does not verify";
                return verified;
            }

            using var rsa = issuer.GetRSAPublicKey();
            if (rsa is null)
            {
                error = "the issuer has no RSA public key";
                return false;
            }

            var ok = rsa.VerifyData(
                tbs,
                signature,
                algorithm.Hash,
                RSASignaturePadding.Pkcs1
            );
            error = ok ? string.Empty : "the signature does not verify";
            return ok;
        }
        catch (CryptographicException)
        {
            // The framework's own message must not travel: this reason reaches an HTTP 400 on the
            // API's write path, and internal exception detail belongs in logs, not responses
            // (Security & Cryptography Requirements — "No raw exception detail to callers").
            error = "its signature could not be verified";
            return false;
        }
    }

    /// <summary>
    /// The certificate signature algorithms we can verify. Anything absent is refused rather
    /// than assumed valid — RSASSA-PSS is intentionally not here: no CA in this product's path
    /// issues with it, and guessing its parameters would be worse than an explicit refusal.
    /// </summary>
    private static readonly Dictionary<
        string,
        (HashAlgorithmName Hash, bool IsEcdsa)
    > SignatureAlgorithms = new()
    {
        ["1.2.840.113549.1.1.5"] = (HashAlgorithmName.SHA1, false), // sha1WithRSA
        ["1.2.840.113549.1.1.11"] = (HashAlgorithmName.SHA256, false), // sha256WithRSA
        ["1.2.840.113549.1.1.12"] = (HashAlgorithmName.SHA384, false), // sha384WithRSA
        ["1.2.840.113549.1.1.13"] = (HashAlgorithmName.SHA512, false), // sha512WithRSA
        ["1.2.840.10045.4.1"] = (HashAlgorithmName.SHA1, true), // ecdsa-with-SHA1
        ["1.2.840.10045.4.3.2"] = (HashAlgorithmName.SHA256, true), // ecdsa-with-SHA256
        ["1.2.840.10045.4.3.3"] = (HashAlgorithmName.SHA384, true), // ecdsa-with-SHA384
        ["1.2.840.10045.4.3.4"] = (HashAlgorithmName.SHA512, true), // ecdsa-with-SHA512
    };

    /// <summary>
    /// Compares the key's public half against the leaf's public key, byte for byte. This is an
    /// exact cryptographic match — it does not rely on subject names lining up.
    /// </summary>
    private static bool KeyMatchesCertificate(AsymmetricAlgorithm privateKey, X509Certificate2 leaf)
    {
        try
        {
            var fromKey = privateKey.ExportSubjectPublicKeyInfo();
            var fromCertificate = leaf.PublicKey.ExportSubjectPublicKeyInfo();
            return CryptographicOperations.FixedTimeEquals(fromKey, fromCertificate);
        }
        catch (CryptographicException)
        {
            // An unexportable or mismatched-algorithm key is a refusal, never an acceptance.
            return false;
        }
    }

    private static (string Algorithm, int KeySizeBits) DescribePublicKey(X509Certificate2 leaf)
    {
        using var rsa = leaf.GetRSAPublicKey();
        if (rsa is not null)
        {
            return ("RSA", rsa.KeySize);
        }

        using var ecdsa = leaf.GetECDsaPublicKey();
        if (ecdsa is not null)
        {
            return ("ECDSA", ecdsa.KeySize);
        }

        return (leaf.PublicKey.Oid.FriendlyName ?? leaf.PublicKey.Oid.Value ?? "unknown", 0);
    }

    private static IReadOnlyList<string> ReadDnsNames(X509Certificate2 leaf)
    {
        var raw = leaf.Extensions[SubjectAlternativeNameOid];
        if (raw is null)
        {
            return [];
        }

        try
        {
            var san = new X509SubjectAlternativeNameExtension(raw.RawData, raw.Critical);
            return san.EnumerateDnsNames().ToList();
        }
        catch (CryptographicException)
        {
            // A malformed SAN extension costs us the display list, never the validation result.
            return [];
        }
    }
}
