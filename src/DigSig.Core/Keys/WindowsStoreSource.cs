using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DigSig.Core.Keys;

/// <summary>
/// Certificates from the Windows "Personal" store (the original's "WKS" mode), e.g. a SafeNet/IDPrime token via its minidriver.
/// </summary>
/// <remarks>
/// The original (Java SunMSCAPI) re-loaded the store and acquired the private key of every certificate on each request,
/// so with several smart cards around Windows asked "Select a smart card device… requires a different smart card".
/// Here no key is touched while listing: smart-card keys are matched against the containers on the inserted cards
/// (enumerated silently), and only the selected certificate's key is opened, when signing.
/// </remarks>
[SupportedOSPlatform("windows")]
public static class WindowsStoreSource
{
    private const string SmartCardKsp = "Microsoft Smart Card Key Storage Provider";

    // TPM / Windows Hello device keys: never document-signing certificates.
    private static readonly string[] DeviceKeyProviders = ["Microsoft Platform Crypto Provider", "Microsoft Passport Key Storage Provider"];

    public static List<CertificateEntry> List()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var onCards = SmartCardContainers();
        var result = new List<CertificateEntry>();
        foreach (var cert in store.Certificates)
        {
            var info = cert.HasPrivateKey ? GetKeyProvInfo(cert) : null;
            if (info is null || DeviceKeyProviders.Contains(info.Value.Provider) ||
                cert.PublicKey.Oid.Value != "1.2.840.113549.1.1.1" || IsSelfSigned(cert) || !CanSign(cert))
            {
                cert.Dispose();
                continue;
            }
            var label = IsSmartCardProvider(info.Value.Provider) ? "Smart card / USB token" : "Windows certificate store";
            result.Add(new CertificateEntry("win:" + cert.Thumbprint, cert, CertificateSourceKind.WindowsStore, label, ProbeKey(cert, onCards)));
        }
        return result;
    }

    public static ISigningIdentity Open(string thumbprint)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        if (found.Count == 0) throw new SignerException("The selected certificate is no longer in the Windows certificate store.");
        return new WindowsStoreIdentity(found[0]);
    }

    private static bool IsSelfSigned(X509Certificate2 cert) => cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData);

    private static bool CanSign(X509Certificate2 cert)
    {
        var ku = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        return ku is null || (ku.KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)) != 0;
    }

    private static bool IsSmartCardProvider(string provider) =>
        provider is SmartCardKsp or "Microsoft Base Smart Card Crypto Provider";

    /// <summary>True when the key is usable without any UI: its card is inserted, or it is a software key.</summary>
    public static bool ProbeKey(X509Certificate2 cert, HashSet<string>? onCards = null)
    {
        var info = GetKeyProvInfo(cert);
        if (info is null) return false;
        var (container, provider, provType, flags, keySpec) = info.Value;
        // The smart card KSP happily opens a handle for a card that is not there, so ask the cards instead.
        if (IsSmartCardProvider(provider)) return (onCards ?? SmartCardContainers()).Contains(container);
        try
        {
            if (provType == 0)
            {
                var options = CngKeyOpenOptions.Silent | ((flags & CryptMachineKeyset) != 0 ? CngKeyOpenOptions.MachineKey : 0);
                using var key = CngKey.Open(container, new CngProvider(provider), options);
                return true;
            }
            var csp = new CspParameters((int)provType, provider, container)
            {
                Flags = CspProviderFlags.UseExistingKey | CspProviderFlags.NoPrompt |
                        ((flags & CryptMachineKeyset) != 0 ? CspProviderFlags.UseMachineKeyStore : 0),
                KeyNumber = (int)keySpec,
            };
            using var rsa = new RSACryptoServiceProvider(csp);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Key container names on all inserted smart cards, enumerated with NCRYPT_SILENT_FLAG (no PIN, no dialogs).</summary>
    public static HashSet<string> SmartCardContainers()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (SCardEstablishContext(ScardScopeSystem, IntPtr.Zero, IntPtr.Zero, out var context) != 0) return result;
        string[] readers;
        try
        {
            var length = 0;
            if (SCardListReaders(context, null, null, ref length) != 0 || length == 0) return result;
            var buffer = new char[length];
            if (SCardListReaders(context, null, buffer, ref length) != 0) return result;
            readers = new string(buffer).Split('\0', StringSplitOptions.RemoveEmptyEntries);
        }
        finally
        {
            SCardReleaseContext(context);
        }

        if (NCryptOpenStorageProvider(out var provider, SmartCardKsp, 0) != 0) return result;
        try
        {
            foreach (var reader in readers)
            {
                var scope = @"\\.\" + reader + @"\";
                var state = IntPtr.Zero;
                try
                {
                    while (NCryptEnumKeys(provider, scope, out var keyName, ref state, NcryptSilentFlag) == 0)
                    {
                        result.Add(Marshal.PtrToStructure<NCryptKeyName>(keyName).pszName);
                        NCryptFreeBuffer(keyName);
                    }
                }
                finally
                {
                    if (state != IntPtr.Zero) NCryptFreeBuffer(state);
                }
            }
        }
        finally
        {
            NCryptFreeObject(provider);
        }
        return result;
    }

    private const uint CertKeyProvInfoPropId = 2;
    private const uint CryptMachineKeyset = 0x20;
    private const int ScardScopeSystem = 2;
    private const int NcryptSilentFlag = 0x40;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CRYPT_KEY_PROV_INFO
    {
        public string pwszContainerName;
        public string pwszProvName;
        public uint dwProvType;
        public uint dwFlags;
        public uint cProvParam;
        public IntPtr rgProvParam;
        public uint dwKeySpec;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NCryptKeyName
    {
        public string pszName;
        public string pszAlgid;
        public int dwLegacyKeySpec;
        public int dwFlags;
    }

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CertGetCertificateContextProperty(IntPtr pCertContext, uint dwPropId, IntPtr pvData, ref uint pcbData);

    [DllImport("winscard.dll")]
    private static extern int SCardEstablishContext(int dwScope, IntPtr pvReserved1, IntPtr pvReserved2, out IntPtr phContext);

    [DllImport("winscard.dll", CharSet = CharSet.Unicode, EntryPoint = "SCardListReadersW")]
    private static extern int SCardListReaders(IntPtr hContext, string? mszGroups, char[]? mszReaders, ref int pcchReaders);

    [DllImport("winscard.dll")]
    private static extern int SCardReleaseContext(IntPtr hContext);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptEnumKeys(IntPtr hProvider, string pszScope, out IntPtr ppKeyName, ref IntPtr ppEnumState, int dwFlags);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptFreeBuffer(IntPtr pvInput);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptFreeObject(IntPtr hObject);

    private static (string Container, string Provider, uint ProvType, uint Flags, uint KeySpec)? GetKeyProvInfo(X509Certificate2 cert)
    {
        uint size = 0;
        if (!CertGetCertificateContextProperty(cert.Handle, CertKeyProvInfoPropId, IntPtr.Zero, ref size)) return null;
        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            if (!CertGetCertificateContextProperty(cert.Handle, CertKeyProvInfoPropId, buffer, ref size)) return null;
            var info = Marshal.PtrToStructure<CRYPT_KEY_PROV_INFO>(buffer);
            return (info.pwszContainerName, info.pwszProvName, info.dwProvType, info.dwFlags, info.dwKeySpec);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private sealed class WindowsStoreIdentity(X509Certificate2 certificate) : ISigningIdentity, IDisposable
    {
        // Kept open between requests so Windows / the token driver can reuse the PIN it already asked for.
        private RSA? _key;

        public X509Certificate2 Certificate { get; } = certificate;
        public IReadOnlyList<X509Certificate2> ExtraCertificates { get; } = [];

        public byte[] SignSha1(byte[] data)
        {
            if (!ProbeKey(Certificate))
            {
                var name = Certificate.GetNameInfo(X509NameType.SimpleName, false);
                throw new SignerException($"The token with the certificate \"{name}\" is not plugged in.");
            }
            // Opening the key for real may show the token's PIN dialog; that is expected.
            _key ??= Certificate.GetRSAPrivateKey() ?? throw new SignerException("The certificate does not have an RSA key.");
            try
            {
                return _key.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            }
            catch (CryptographicException ex)
            {
                throw new SignerException("The token refused to sign: " + ex.Message, ex);
            }
        }

        public void Dispose()
        {
            _key?.Dispose();
            Certificate.Dispose();
        }
    }
}
