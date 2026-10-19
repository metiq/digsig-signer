using System.IO.Compression;
using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DigSig.Core.Server;

/// <summary>
/// The certificate for https://localhost:8443. Each installation generates its own; users who already trust the
/// certificate of the original DigSig can import it from their copy of the original .jar instead.
/// </summary>
public static class HttpsCertificate
{
    // Location and password of the localhost certificate inside the original digsig-signer jar.
    private const string OriginalJarEntry = "BOOT-INF/classes/cdeps_https_singing_app.p12";
    private const string OriginalPassword = "cdepshttps";

    public static string DefaultPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DigSig", "https.pfx");

    /// <summary>Loads the certificate stored at <paramref name="pfxPath"/>, creating a new self-signed one the first time.</summary>
    public static X509Certificate2 LoadOrCreate(string? pfxPath = null)
    {
        pfxPath ??= DefaultPath;
        if (!File.Exists(pfxPath))
        {
            using var created = CreateSelfSigned();
            Save(created, pfxPath);
        }
        return X509CertificateLoader.LoadPkcs12FromFile(pfxPath, "", KeyStorageFlags);
    }

    /// <summary>A new self-signed certificate for localhost / 127.0.0.1 / ::1.</summary>
    public static X509Certificate2 CreateSelfSigned()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=DigSig localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        san.AddIpAddress(IPAddress.IPv6Loopback);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
        // Round-trip through PKCS#12 so the key is usable by the TLS stack on every OS.
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pkcs12, ""), "", KeyStorageFlags);
    }

    /// <summary>
    /// Copies the localhost certificate out of an original digsig-signer .jar (e.g. digsig-signer-1.3.7.jar) to
    /// <paramref name="pfxPath"/>, so browsers that trusted the original keep working without a new warning.
    /// </summary>
    public static X509Certificate2 ImportFromOriginalJar(string jarPath, string? pfxPath = null)
    {
        using var zip = ZipFile.OpenRead(jarPath);
        var entry = zip.GetEntry(OriginalJarEntry)
            ?? throw new SignerException("This file does not look like the original DigSig application (no HTTPS certificate inside).");
        using var stream = entry.Open();
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        using var original = X509CertificateLoader.LoadPkcs12(ms.ToArray(), OriginalPassword, KeyStorageFlags | X509KeyStorageFlags.Exportable);
        Save(original, pfxPath ?? DefaultPath);
        return LoadOrCreate(pfxPath);
    }

    /// <summary>Adds the certificate to the current user's trusted roots; Windows asks the user to confirm.</summary>
    [SupportedOSPlatform("windows")]
    public static void TrustInWindows(X509Certificate2 certificate)
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(X509CertificateLoader.LoadCertificate(certificate.RawData));
    }

    [SupportedOSPlatform("windows")]
    public static bool IsTrustedInWindows(X509Certificate2 certificate)
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindByThumbprint, certificate.Thumbprint, validOnly: false).Count > 0;
    }

    private static void Save(X509Certificate2 certificate, string pfxPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(pfxPath)!);
        File.WriteAllBytes(pfxPath, certificate.Export(X509ContentType.Pkcs12, ""));
    }

    // SChannel (Windows) and macOS cannot serve TLS from an ephemeral key.
    private static X509KeyStorageFlags KeyStorageFlags =>
        OperatingSystem.IsLinux() ? X509KeyStorageFlags.EphemeralKeySet : X509KeyStorageFlags.DefaultKeySet;
}
