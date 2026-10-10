using System.Buffers.Binary;
using System.Text;

namespace BellaBaxter.Crypto;

/// <summary>
/// Where a secret value belongs: sealed into its <c>bellabaxter:v2:</c> envelope as associated data, so
/// the same ciphertext read anywhere else fails to open (spec 077, FR-001/FR-002).
/// </summary>
/// <remarks>
/// <para>Identifiers, not slugs: renaming a project or an environment must leave its values readable.
/// The secret key is bound exactly as stored at the provider, since a secret has no other identity.</para>
///
/// <para>The associated data is a list of fields, each a 4-byte big-endian length followed by its UTF-8
/// bytes: the scheme, the tenant, the project, the environment (or <see cref="SharedScope"/>) and the
/// key. Length prefixes keep it unambiguous for any key name. Every implementation, the API, the CLI and
/// any SDK, must produce these exact bytes; <c>SDK_CONTRACT.md</c> carries known-answer vectors.</para>
/// </remarks>
public sealed record SecretBinding
{
    /// <summary>The scheme bound into every <c>v2</c> envelope.</summary>
    public const string Scheme = "bellabaxter:v2";

    /// <summary>The scope a project's shared (<c>_global</c>) values are bound to.</summary>
    public const string SharedScope = "_global";

    private SecretBinding(Guid tenantId, Guid projectId, Guid? environmentId, string secretKey)
    {
        if (tenantId == Guid.Empty)
            throw new ArgumentException("A binding needs a tenant.", nameof(tenantId));
        if (projectId == Guid.Empty)
            throw new ArgumentException("A binding needs a project.", nameof(projectId));
        if (environmentId == Guid.Empty)
            throw new ArgumentException("A binding needs an environment, or the shared scope.", nameof(environmentId));
        if (string.IsNullOrEmpty(secretKey))
            throw new ArgumentException("A binding needs the secret's key.", nameof(secretKey));

        TenantId = tenantId;
        ProjectId = projectId;
        EnvironmentId = environmentId;
        SecretKey = secretKey;
    }

    public Guid TenantId { get; }
    public Guid ProjectId { get; }

    /// <summary>The environment the value belongs to; null for a project-shared value.</summary>
    public Guid? EnvironmentId { get; }

    public string SecretKey { get; }

    /// <summary>Whether the value is a project-shared (<c>_global</c>) value.</summary>
    public bool IsShared => EnvironmentId is null;

    /// <summary>A value of one environment.</summary>
    public static SecretBinding ForEnvironment(Guid tenantId, Guid projectId, Guid environmentId, string secretKey) =>
        new(tenantId, projectId, environmentId, secretKey);

    /// <summary>A project-shared (<c>_global</c>) value, readable from every environment of the project.</summary>
    public static SecretBinding ForShared(Guid tenantId, Guid projectId, string secretKey) =>
        new(tenantId, projectId, null, secretKey);

    /// <summary>The associated-data bytes sealed with the value.</summary>
    public byte[] ToAssociatedData()
    {
        string[] fields =
        [
            Scheme,
            TenantId.ToString("N"),
            ProjectId.ToString("N"),
            EnvironmentId?.ToString("N") ?? SharedScope,
            SecretKey,
        ];

        var encoded = fields.Select(Encoding.UTF8.GetBytes).ToArray();
        var result = new byte[encoded.Sum(f => 4 + f.Length)];
        var offset = 0;
        foreach (var field in encoded)
        {
            BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(offset, 4), field.Length);
            field.CopyTo(result, offset + 4);
            offset += 4 + field.Length;
        }

        return result;
    }
}
