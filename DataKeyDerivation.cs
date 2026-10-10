using System.Security.Cryptography;
using System.Text;

namespace BellaBaxter.Crypto;

/// <summary>
/// spec 077 — the key that opens one environment's values, and the key that opens a project's shared
/// values, both DERIVED from a project data key (decided by jjchiw, 2026-10-09).
/// </summary>
/// <remarks>
/// <para>HKDF-SHA256 (RFC 5869), empty salt, 32-byte output. The input is already a uniformly random
/// 32-byte key, so a salt adds nothing. Nothing new is stored: rotating the project key rotates every
/// derived key, a deleted environment leaves nothing to destroy, and recovery is unchanged.</para>
///
/// <para>The project id is in <c>info</c> because a project without a key of its own uses the TENANT
/// key; without it, every such project would derive the same shared key.</para>
///
/// <para>The caller owns the returned array and zeroes it (<see cref="CryptographicOperations.ZeroMemory"/>).</para>
/// </remarks>
public static class DataKeyDerivation
{
    private const int KeySize = 32;

    /// <summary>The key that opens <paramref name="environmentId"/>'s values.</summary>
    public static byte[] ForEnvironment(ReadOnlySpan<byte> projectDataKey, Guid projectId, Guid environmentId) =>
        Derive(projectDataKey, $"bellabaxter/v2/env/{projectId:N}/{environmentId:N}");

    /// <summary>The key that opens the project's shared (<c>_global</c>) values.</summary>
    public static byte[] ForShared(ReadOnlySpan<byte> projectDataKey, Guid projectId) =>
        Derive(projectDataKey, $"bellabaxter/v2/shared/{projectId:N}");

    /// <summary>The key for <paramref name="binding"/>'s scope.</summary>
    public static byte[] For(ReadOnlySpan<byte> projectDataKey, SecretBinding binding) =>
        binding.EnvironmentId is { } environmentId
            ? ForEnvironment(projectDataKey, binding.ProjectId, environmentId)
            : ForShared(projectDataKey, binding.ProjectId);

    private static byte[] Derive(ReadOnlySpan<byte> projectDataKey, string info)
    {
        if (projectDataKey.Length != KeySize)
            throw new ArgumentException($"A data key must be {KeySize} bytes.", nameof(projectDataKey));

        var derived = new byte[KeySize];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, projectDataKey, derived, ReadOnlySpan<byte>.Empty, Encoding.UTF8.GetBytes(info));
        return derived;
    }
}
