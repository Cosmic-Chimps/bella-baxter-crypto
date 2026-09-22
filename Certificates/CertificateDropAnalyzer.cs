using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace BellaBaxter.Crypto.Certificates;

// spec 057 (T005) — the judging half of spec 020's CertificateDropReader, with the filesystem taken
// out. Given a folder's name and its files, decide what that folder holds.
//
// The split is the whole point of this class: the CLI reads a directory and the console opens an
// archive, but neither may decide which file is the certificate, which is the key, or what the
// certificate is called. Those answers come from here, so the two surfaces cannot disagree
// (spec 057 FR-008, FR-030).

public static class CertificateDropAnalyzer
{
    /// <summary>
    /// A drop should never contain anything large. A file over this is ignored rather than slurped.
    /// </summary>
    public const int MaxFileBytes = 1024 * 1024;

    /// <summary>
    /// Classifies one folder of a drop. A folder that yields no certificate material is SKIPPED with
    /// a reason, never failed — that is what keeps incidental files and stray folders harmless.
    /// </summary>
    public static CertificateDropEntry Analyze(string folderName, IEnumerable<DropFile> files)
    {
        var chains = new List<string>();
        var keys = new List<string>();

        foreach (var file in files)
        {
            var content = file.Content;

            var hasCertificate = CertificateBundleReader.SplitCertificateBlocks(content).Count > 0;
            var keyBlock = CertificateBundleReader.ExtractPrivateKeyBlock(content);

            if (hasCertificate)
            {
                chains.Add(content);
            }

            if (keyBlock is not null)
            {
                // A combined file holding both blocks counts once for each.
                keys.Add(hasCertificate ? keyBlock : content);
            }
        }

        if (chains.Count == 0)
        {
            return new CertificateDropEntry
            {
                SourceDirectory = folderName,
                SkipReason = DropEntrySkipReason.NoCertificate,
                SkipDetail = "no file in this folder contains a certificate.",
            };
        }

        if (chains.Count > 1)
        {
            return new CertificateDropEntry
            {
                SourceDirectory = folderName,
                SkipReason = DropEntrySkipReason.MultipleCertificates,
                SkipDetail =
                    $"{chains.Count} files contain certificates; a folder must hold exactly one.",
            };
        }

        if (keys.Count == 0)
        {
            return new CertificateDropEntry
            {
                SourceDirectory = folderName,
                ChainPem = chains[0],
                SkipReason = DropEntrySkipReason.NoPrivateKey,
                SkipDetail = "no file in this folder contains a private key.",
            };
        }

        if (keys.Count > 1)
        {
            return new CertificateDropEntry
            {
                SourceDirectory = folderName,
                ChainPem = chains[0],
                SkipReason = DropEntrySkipReason.MultiplePrivateKeys,
                SkipDetail =
                    $"{keys.Count} files contain private keys; a folder must hold exactly one.",
            };
        }

        var commonName = TryReadCommonName(chains[0]);
        if (commonName is null)
        {
            return new CertificateDropEntry
            {
                SourceDirectory = folderName,
                ChainPem = chains[0],
                PrivateKeyPem = keys[0],
                SkipReason = DropEntrySkipReason.UnreadableCertificate,
                SkipDetail = "the certificate's common name could not be read.",
            };
        }

        return new CertificateDropEntry
        {
            SourceDirectory = folderName,
            ChainPem = chains[0],
            PrivateKeyPem = keys[0],
            CommonName = commonName,
        };
    }

    /// <summary>The leaf's common name — the drop entry's only trustworthy identity.</summary>
    private static string? TryReadCommonName(string chainPem)
    {
        var blocks = CertificateBundleReader.SplitCertificateBlocks(chainPem);
        if (blocks.Count == 0)
        {
            return null;
        }

        try
        {
            using var leaf = X509Certificate2.CreateFromPem(blocks[0]);
            var commonName = leaf.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            return string.IsNullOrWhiteSpace(commonName) ? null : commonName;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            return null;
        }
    }
}
