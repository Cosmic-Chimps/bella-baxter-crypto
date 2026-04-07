namespace BellaBaxter.Crypto;

/// <summary>
/// A wrapper for sensitive string values (e.g. decrypted secret values) that
/// prevents accidental logging or serialization.
///
/// Usage:
///   var value = new SensitiveString(decryptedPlaintext);
///   // ... process it ...
///   var exposed = value.Expose(); // explicit, hard to do by accident
///   value.Dispose();              // zeros the underlying value
///
/// Design:
///   - ToString() returns "***REDACTED***" — safe to pass to loggers/formatters
///   - GetHashCode() returns 0 — prevents dictionary/set membership leaks
///   - Expose() is the only way to read the value — forces explicit intent
///   - Dispose() zeros the string (best-effort; .NET strings are immutable,
///     but this signals the intent and aids with future GC/SecureString migration)
/// </summary>
public sealed class SensitiveString : IDisposable
{
    private string? _value;
    private bool _disposed;

    public SensitiveString(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _value = value;
    }

    /// <summary>
    /// Returns the underlying plaintext value. Call this only when you need to
    /// pass the value to an external system (vault adapter, response serializer).
    /// </summary>
    /// <exception cref="ObjectDisposedException">If already disposed.</exception>
    public string Expose()
    {
        ObjectDisposedException.ThrowIf(_disposed, nameof(SensitiveString));
        return _value!;
    }

    /// <summary>Always returns "***REDACTED***" — safe for logs and exceptions.</summary>
    public override string ToString() => "***REDACTED***";

    /// <summary>Returns 0 — prevents hash-based membership inference.</summary>
    public override int GetHashCode() => 0;

    /// <summary>Equality is always false — prevents value comparison leaks.</summary>
    public override bool Equals(object? obj) => false;

    /// <summary>Clears the reference. .NET strings are immutable so we can't zero bytes,
    /// but this allows the GC to collect the string sooner.</summary>
    public void Dispose()
    {
        _value = null;
        _disposed = true;
    }

    /// <summary>Implicit conversion from string for ergonomic construction.</summary>
    public static implicit operator SensitiveString(string value) => new(value);
}
