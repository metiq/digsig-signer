using System.Security.Cryptography.X509Certificates;

namespace DigSig.Core.Keys;

/// <summary>A certificate plus the ability to produce RSA PKCS#1 v1.5 signatures with its private key.</summary>
public interface ISigningIdentity
{
    X509Certificate2 Certificate { get; }

    /// <summary>Certificates available to build the chain (intermediates/roots found next to the key).</summary>
    IReadOnlyList<X509Certificate2> ExtraCertificates { get; }

    /// <summary>Signs <paramref name="data"/> with RSA PKCS#1 v1.5 over SHA-1 (what CDEPS expects).</summary>
    byte[] SignSha1(byte[] data);
}
