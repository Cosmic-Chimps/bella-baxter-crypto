namespace BellaBaxter.Crypto.Certificates;

// spec 020 — the result type of certificate-bundle validation.
//
// Validation NEVER throws its way out and NEVER degrades to a weaker path: it returns either
// Valid (with the derived facts) or Rejected (with a machine-readable kind and a human reason).
// Both call sites — the CLI import and the API write path — fail closed on Rejected
// (Constitution I).

/// <summary>Why a certificate bundle was refused. <see cref="None"/> only on success.</summary>
public enum CertificateBundleRejection
{
    None = 0,

    /// <summary>No certificate block could be parsed from the chain.</summary>
    UnreadableChain,

    /// <summary>The first block is not the leaf (e.g. a root-first chain).</summary>
    ChainNotLeafFirst,

    /// <summary>A block is not issued by the block that follows it.</summary>
    BrokenChainOrder,

    /// <summary>The private key could not be parsed.</summary>
    UnreadableKey,

    /// <summary>The private key is password-protected. The drop's contract is unencrypted keys.</summary>
    EncryptedKey,

    /// <summary>The private key's public half does not match the leaf's public key.</summary>
    KeyDoesNotMatchCertificate,

    /// <summary>The leaf carries no readable common name.</summary>
    MissingCommonName,

    /// <summary>The leaf is expired or not yet valid.</summary>
    OutsideValidityWindow,
}

/// <summary>The outcome of validating one certificate bundle.</summary>
public sealed record CertificateBundleValidation
{
    private CertificateBundleValidation(
        CertificateBundleRejection rejection,
        string? reason,
        CertificateFacts? facts
    )
    {
        Rejection = rejection;
        Reason = reason;
        Facts = facts;
    }

    public CertificateBundleRejection Rejection { get; }

    /// <summary>A human-readable reason, safe to show an operator. Null when valid.</summary>
    public string? Reason { get; }

    /// <summary>The derived facts. Non-null exactly when <see cref="IsValid"/>.</summary>
    public CertificateFacts? Facts { get; }

    public bool IsValid => Rejection == CertificateBundleRejection.None;

    public static CertificateBundleValidation Valid(CertificateFacts facts) =>
        new(CertificateBundleRejection.None, null, facts);

    public static CertificateBundleValidation Rejected(
        CertificateBundleRejection rejection,
        string reason
    ) => new(rejection, reason, null);
}
