namespace BellaBaxter.Crypto.Certificates;

// spec 020 (T006, T011) — the derived, NON-SENSITIVE facts about a certificate.
//
// This is the only thing that crosses from certificate content into anything Bella stores,
// displays, or logs. Every field is a fact about a PUBLIC certificate: nothing here is, or
// can be derived into, private key material (Constitution II).

/// <summary>Descriptive facts read out of a certificate bundle's leaf certificate.</summary>
public sealed record CertificateFacts(
    /// <summary>Leaf subject common name — the certificate's identity.</summary>
    string CommonName,
    /// <summary>DNS entries from the leaf's subject-alternative-name extension.</summary>
    IReadOnlyList<string> SubjectAlternativeNames,
    /// <summary>The leaf's issuer distinguished name.</summary>
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    /// <summary>Public key algorithm of the leaf, e.g. <c>RSA</c> or <c>ECDSA</c>.</summary>
    string KeyAlgorithm,
    int KeySizeBits,
    /// <summary>Lowercase hex SHA-256 over the leaf's raw bytes.</summary>
    string Sha256Fingerprint,
    /// <summary>How many certificate blocks the delivered chain carried.</summary>
    int ChainLength,
    /// <summary>True when the delivered chain ends in a self-signed root.</summary>
    bool ChainIncludesSelfSignedRoot
)
{
    /// <summary>Whole days from <paramref name="now"/> until expiry; negative once expired.</summary>
    public int DaysRemaining(DateTimeOffset now) => (int)Math.Floor((NotAfter - now).TotalDays);
}
