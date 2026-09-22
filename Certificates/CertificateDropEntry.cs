namespace BellaBaxter.Crypto.Certificates;

// spec 057 (T003) — moved here from BellaCli so BOTH the CLI import and the console import read one
// set of rules. Originally spec 020's CertificateDropReader types.
//
// Two rules drive everything about a drop, and they are the reason these types are shaped this way:
//
//  1. Files are classified by their PEM CONTENT, never by name. The customer's drop happens to use
//     key.pem plus <cn_with_underscores>.pem, but a drop whose files are named differently must still
//     import (spec 020 FR-003).
//  2. Identity comes from the leaf certificate's common name, never from the folder or file name
//     (spec 020 FR-002). In the real drop the folder is "RoadRunner", the file is "roadrunner_...", and
//     the common name is "RoadRunner.acme.com.mx" — only the certificate is trustworthy.

/// <summary>Why a subdirectory produced no certificate.</summary>
public enum DropEntrySkipReason
{
    None = 0,
    NoCertificate,
    NoPrivateKey,
    MultipleCertificates,
    MultiplePrivateKeys,
    UnreadableCertificate,
}

/// <summary>One file within a drop folder: its name, and its content as text.</summary>
/// <remarks>
/// <paramref name="Name"/> is carried for messages only. Nothing classifies on it.
/// </remarks>
public sealed record DropFile(string Name, string Content);

/// <summary>One subdirectory of a drop, and what was found in it.</summary>
public sealed record CertificateDropEntry
{
    /// <summary>Directory name — a human label, never an identity.</summary>
    public required string SourceDirectory { get; init; }

    public string? ChainPem { get; init; }
    public string? PrivateKeyPem { get; init; }

    /// <summary>The common name parsed from the leaf, when the material was readable.</summary>
    public string? CommonName { get; init; }

    public DropEntrySkipReason SkipReason { get; init; }
    public string? SkipDetail { get; init; }

    public bool HasMaterial =>
        SkipReason == DropEntrySkipReason.None
        && !string.IsNullOrEmpty(ChainPem)
        && !string.IsNullOrEmpty(PrivateKeyPem);
}

/// <summary>Everything a drop yielded.</summary>
public sealed record CertificateDrop(string RootPath, IReadOnlyList<CertificateDropEntry> Entries);
