using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DigSig.Core.Keys;

/// <summary>Software key from a .pfx/.p12 file (the original's "PFX" container type).</summary>
public sealed class PfxIdentity : ISigningIdentity, IDisposable
{
    private readonly X509Certificate2Collection _all;

    public PfxIdentity(string path, string password)
    {
        var flags = OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet;
        _all = X509CertificateLoader.LoadPkcs12CollectionFromFile(path, password, flags);
        // Like PfxKeyStore.getLastAlias: the entry that holds a private key.
        Certificate = _all.LastOrDefault(c => c.HasPrivateKey)
            ?? throw new CryptographicException($"No private key found in {Path.GetFileName(path)}.");
        ExtraCertificates = _all.Where(c => !ReferenceEquals(c, Certificate)).ToList();
    }

    public X509Certificate2 Certificate { get; }
    public IReadOnlyList<X509Certificate2> ExtraCertificates { get; }

    public byte[] SignSha1(byte[] data)
    {
        using var rsa = Certificate.GetRSAPrivateKey() ?? throw new CryptographicException("The certificate does not have an RSA key.");
        return rsa.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
    }

    public void Dispose()
    {
        foreach (var c in _all) c.Dispose();
    }
}
