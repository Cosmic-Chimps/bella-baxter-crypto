using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Xml.Linq;

namespace BellaBaxter.Crypto.Certificates;

// spec 057 (T004) — moved here from BellaCli/ManifestReader.cs so the CLI import and the console
// import pair passphrases by one rule. Reads from BYTES rather than a path: the console has no
// filesystem, and mis-pairing a passphrase is exactly the judgement this class refuses to risk.
//
// Originally spec 020 (T021). The manifest is ADVISORY: it exists to catch an incomplete delivery,
// never to supply identity (that comes from the certificate itself) and never to gate an import. Its
// passphrase column is not needed to deploy anything — see specs/020-cert-bundle-import/research.md D11.
//
// Deliberately NO new dependency: the sheet is two columns, and a spreadsheet library would be
// several megabytes of cargo for a two-column read (spec 020 research D2). An unrecognised sheet
// shape FAILS LOUDLY pointing at the csv fallback rather than guessing and mis-pairing passphrases.

/// <summary>One row of the manifest: a common name and its passphrase.</summary>
/// <remarks>
/// <see cref="Passphrase"/> is a secret. It must never be written to output, logs, or telemetry
/// in any mode (spec 020 FR-013, spec 057 FR-021).
/// </remarks>
public sealed record ManifestRow(string CommonName, string Passphrase);

/// <summary>The manifest could not be understood. Carries operator-actionable guidance.</summary>
public sealed class ManifestFormatException(string message) : Exception(message);

public static class CertificateManifestReader
{
    private const string SpreadsheetNamespace =
        "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

    /// <summary>Header spellings accepted for the common-name column.</summary>
    private static readonly string[] CommonNameHeaders =
    [
        "common name",
        "commonname",
        "cn",
        "nombre",
    ];

    /// <summary>Header spellings accepted for the passphrase column, accents included or not.</summary>
    private static readonly string[] PassphraseHeaders =
    [
        "contraseña",
        "contrasena",
        "password",
        "passphrase",
        "clave",
    ];

    /// <summary>
    /// Reads a manifest from its bytes. <paramref name="fileName"/> picks the reader by extension
    /// (<c>.xlsx</c>, <c>.csv</c>, <c>.tsv</c>) and names the file in any refusal.
    /// </summary>
    /// <exception cref="ManifestFormatException">The file's shape was not recognised.</exception>
    public static IReadOnlyList<ManifestRow> Read(string fileName, byte[] content)
    {
        var displayName = Path.GetFileName(fileName);

        var rows = Path.GetExtension(fileName).ToLowerInvariant() switch
        {
            ".xlsx" => ReadSpreadsheet(content, displayName),
            ".csv" => ReadDelimited(content, ','),
            ".tsv" => ReadDelimited(content, '\t'),
            var other => throw new ManifestFormatException(
                $"Manifest format '{other}' is not supported. Supply .xlsx, .csv, or .tsv."
            ),
        };

        return Interpret(rows, displayName);
    }

    /// <summary>
    /// Turns raw cell grids into rows, locating the columns by header. A grid whose header is
    /// unrecognisable is refused with the csv escape hatch named — never silently mis-paired.
    /// </summary>
    private static IReadOnlyList<ManifestRow> Interpret(
        IReadOnlyList<IReadOnlyList<string>> grid,
        string displayName
    )
    {
        if (grid.Count == 0)
        {
            throw new ManifestFormatException($"Manifest '{displayName}' is empty.");
        }

        var header = grid[0];
        var nameColumn = FindColumn(header, CommonNameHeaders);
        var passphraseColumn = FindColumn(header, PassphraseHeaders);

        if (nameColumn < 0 || passphraseColumn < 0)
        {
            throw new ManifestFormatException(
                $"Could not find the expected columns in '{displayName}'. A manifest "
                    + "needs a 'Common Name' column and a 'Contraseña' column in its first row. "
                    + "If this sheet has an unusual layout, export it to CSV and pass that instead."
            );
        }

        var rows = new List<ManifestRow>();
        foreach (var line in grid.Skip(1))
        {
            if (nameColumn >= line.Count)
            {
                continue;
            }

            var commonName = line[nameColumn].Trim();
            if (string.IsNullOrEmpty(commonName))
            {
                continue;
            }

            var passphrase =
                passphraseColumn < line.Count ? line[passphraseColumn].Trim() : string.Empty;
            rows.Add(new ManifestRow(commonName, passphrase));
        }

        return rows;
    }

    private static int FindColumn(IReadOnlyList<string> header, string[] accepted)
    {
        for (var i = 0; i < header.Count; i++)
        {
            var cell = Normalize(header[i]);
            if (accepted.Any(a => cell == Normalize(a)))
            {
                return i;
            }
        }

        return -1;
    }

    private static string Normalize(string value) =>
        new string(value.Where(c => !char.IsWhiteSpace(c)).ToArray()).ToLowerInvariant();

    // ── xlsx ─────────────────────────────────────────────────────────────────

    private static IReadOnlyList<IReadOnlyList<string>> ReadSpreadsheet(
        byte[] content,
        string displayName
    )
    {
        ZipArchive archive;
        try
        {
            archive = new ZipArchive(new MemoryStream(content, writable: false), ZipArchiveMode.Read);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        {
            throw new ManifestFormatException(
                $"'{displayName}' could not be opened as a spreadsheet. "
                    + "If it is a legacy .xls file, save it as .xlsx or export it to CSV."
            );
        }

        using (archive)
        {
            var sheet =
                archive.GetEntry("xl/worksheets/sheet1.xml")
                ?? archive
                    .Entries.Where(e =>
                        e.FullName.StartsWith("xl/worksheets/sheet", StringComparison.Ordinal)
                        && e.FullName.EndsWith(".xml", StringComparison.Ordinal)
                    )
                    .OrderBy(e => e.FullName, StringComparer.Ordinal)
                    .FirstOrDefault();

            if (sheet is null)
            {
                throw new ManifestFormatException(
                    $"'{displayName}' contains no worksheet. Export it to CSV instead."
                );
            }

            var sharedStrings = ReadSharedStrings(archive, displayName);

            XDocument document;
            try
            {
                using var stream = sheet.Open();
                document = XDocument.Load(stream);
            }
            catch (System.Xml.XmlException)
            {
                throw new ManifestFormatException(
                    $"The worksheet inside '{displayName}' could not be read. "
                        + "Export it to CSV instead."
                );
            }

            var ns = XNamespace.Get(SpreadsheetNamespace);
            var grid = new List<IReadOnlyList<string>>();

            foreach (var row in document.Descendants(ns + "row"))
            {
                var cells = new List<string>();
                foreach (var cell in row.Elements(ns + "c"))
                {
                    var index = ColumnIndex(cell.Attribute("r")?.Value);
                    while (cells.Count < index)
                    {
                        cells.Add(string.Empty);
                    }

                    cells.Add(CellValue(cell, ns, sharedStrings));
                }

                grid.Add(cells);
            }

            return grid;
        }
    }

    private static List<string> ReadSharedStrings(ZipArchive archive, string displayName)
    {
        var entry = archive.GetEntry("xl/sharedStrings.xml");
        if (entry is null)
        {
            return [];
        }

        var ns = XNamespace.Get(SpreadsheetNamespace);
        using var stream = entry.Open();

        // Refused the same way its sibling refuses a malformed worksheet. Before spec 057 this read
        // an operator's own file at a command line, where an unhandled XmlException was a stack
        // trace they could act on; it now reads bytes submitted over HTTP, where it would be a 500
        // instead of the operator-readable refusal every other malformed manifest gets.
        XDocument document;
        try
        {
            document = XDocument.Load(stream);
        }
        catch (System.Xml.XmlException)
        {
            throw new ManifestFormatException(
                $"The shared strings inside '{displayName}' could not be read. "
                    + "Export it to CSV instead."
            );
        }

        return document
            .Descendants(ns + "si")
            .Select(si => string.Concat(si.Descendants(ns + "t").Select(t => t.Value)))
            .ToList();
    }

    private static string CellValue(XElement cell, XNamespace ns, List<string> sharedStrings)
    {
        var type = cell.Attribute("t")?.Value;

        if (type == "inlineStr")
        {
            return string.Concat(cell.Descendants(ns + "t").Select(t => t.Value));
        }

        var value = cell.Element(ns + "v")?.Value ?? string.Empty;

        if (
            type == "s"
            && int.TryParse(value, CultureInfo.InvariantCulture, out var sharedIndex)
            && sharedIndex >= 0
            && sharedIndex < sharedStrings.Count
        )
        {
            return sharedStrings[sharedIndex];
        }

        return value;
    }

    /// <summary>Zero-based column index from a cell reference such as <c>B12</c>.</summary>
    private static int ColumnIndex(string? cellReference)
    {
        if (string.IsNullOrEmpty(cellReference))
        {
            return 0;
        }

        var index = 0;
        foreach (var character in cellReference)
        {
            if (!char.IsAsciiLetter(character))
            {
                break;
            }

            index = (index * 26) + (char.ToUpperInvariant(character) - 'A' + 1);
        }

        return Math.Max(0, index - 1);
    }

    // ── delimited text ───────────────────────────────────────────────────────

    private static IReadOnlyList<IReadOnlyList<string>> ReadDelimited(byte[] content, char delimiter)
    {
        var grid = new List<IReadOnlyList<string>>();
        foreach (var line in DecodeLines(content))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            grid.Add(SplitLine(line, delimiter));
        }

        return grid;
    }

    /// <summary>
    /// Decodes UTF-8 text and splits it into lines. Stripping the byte-order mark PRESERVES what
    /// <c>File.ReadAllLines</c> did here before the move: it detects and removes one. Excel writes a
    /// BOM when exporting CSV, and left in place it becomes part of the first header cell, so the
    /// column lookup misses and a perfectly good manifest is refused.
    /// </summary>
    private static IEnumerable<string> DecodeLines(byte[] content)
    {
        var text = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetString(content);
        if (text.Length > 0 && text[0] == '﻿')
        {
            text = text[1..];
        }

        return text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>Splits one delimited line, honouring double-quoted fields.</summary>
    private static List<string> SplitLine(string line, char delimiter)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        var quoted = false;

        for (var i = 0; i < line.Length; i++)
        {
            var character = line[i];

            if (quoted)
            {
                if (character == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"')
                    {
                        current.Append('"');
                        i++;
                    }
                    else
                    {
                        quoted = false;
                    }
                }
                else
                {
                    current.Append(character);
                }

                continue;
            }

            if (character == '"')
            {
                quoted = true;
            }
            else if (character == delimiter)
            {
                fields.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(character);
            }
        }

        fields.Add(current.ToString());
        return fields;
    }
}
