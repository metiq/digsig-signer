using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace DigSig.Core.Keys;

/// <summary>
/// A loaded PKCS#11 library (e.g. SafeNet eTPKCS11.dll / libeTPkcs11.so / .dylib). This is the cross-platform path to the token.
/// The library stays loaded for the lifetime of the app; logged-in sessions are kept so the PIN is entered once.
/// </summary>
public sealed class Pkcs11Module : IDisposable
{
    private static readonly Pkcs11InteropFactories Factories = new();
    private readonly IPkcs11Library _library;
    private readonly object _gate = new();

    public Pkcs11Module(string libraryPath)
    {
        LibraryPath = libraryPath;
        try
        {
            _library = Factories.Pkcs11LibraryFactory.LoadPkcs11Library(Factories, libraryPath, AppType.MultiThreaded);
        }
        catch (Exception ex)
        {
            throw new SignerException($"Could not load the PKCS#11 library \"{libraryPath}\": {ex.Message}", ex);
        }
    }

    public string LibraryPath { get; }

    /// <summary>Well-known install locations of the SafeNet / Thales libraries per OS.</summary>
    public static IEnumerable<string> DefaultLibraryCandidates()
    {
        if (OperatingSystem.IsWindows())
        {
            var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            return [Path.Combine(sys, "eTPKCS11.dll"), Path.Combine(pf, @"SafeNet\Authentication\SAC\x64\IDPrimePKCS1164.dll")];
        }
        if (OperatingSystem.IsMacOS())
            return ["/usr/local/lib/libeTPkcs11.dylib", "/Library/Frameworks/eToken.framework/Versions/A/libeToken.dylib", "/usr/local/lib/libIDPrimePKCS11.dylib"];
        return ["/usr/lib/libeTPkcs11.so", "/usr/lib64/libeTPkcs11.so", "/usr/lib/x86_64-linux-gnu/libeTPkcs11.so", "/usr/lib/pkcs11/libeTPkcs11.so", "/usr/lib/libIDPrimePKCS11.so"];
    }

    public static string? FindDefaultLibrary() => DefaultLibraryCandidates().FirstOrDefault(File.Exists);

    /// <summary>Lists certificates on all present tokens. Certificates are public objects, so no PIN is needed.</summary>
    public List<CertificateEntry> List()
    {
        var result = new List<CertificateEntry>();
        lock (_gate)
        {
            foreach (var slot in _library.GetSlotList(SlotsType.WithTokenPresent))
            {
                try
                {
                    var token = slot.GetTokenInfo();
                    using var session = slot.OpenSession(SessionType.ReadOnly);
                    foreach (var (cert, _) in FindCertificates(session))
                    {
                        result.Add(new CertificateEntry($"p11:{token.SerialNumber.Trim()}:{cert.Thumbprint}", cert,
                            CertificateSourceKind.Pkcs11Token, $"Token \"{token.Label.Trim()}\"", IsAvailable: true));
                    }
                }
                catch (Pkcs11Exception)
                {
                    // Token removed while enumerating, or a reader in a bad state: skip it.
                }
            }
        }
        return result;
    }

    /// <param name="pinPrompt">Asked for the PIN when the token is not logged in yet; return null to cancel.</param>
    public ISigningIdentity Open(string tokenSerial, string thumbprint, Func<string, string?> pinPrompt)
    {
        ISession session;
        string tokenLabel;
        X509Certificate2 cert;
        byte[] ckaId;
        List<X509Certificate2> extra;
        lock (_gate)
        {
            var slot = _library.GetSlotList(SlotsType.WithTokenPresent)
                .FirstOrDefault(s => s.GetTokenInfo().SerialNumber.Trim() == tokenSerial)
                ?? throw new SignerException("The token for the selected certificate is not plugged in.");
            tokenLabel = slot.GetTokenInfo().Label.Trim();
            session = slot.OpenSession(SessionType.ReadOnly);
            var certs = FindCertificates(session);
            (cert, ckaId) = certs.FirstOrDefault(c => c.Cert.Thumbprint == thumbprint);
            extra = certs.Select(c => c.Cert).Where(c => c.Thumbprint != thumbprint).ToList();
        }
        try
        {
            if (cert is null) throw new SignerException("The selected certificate was not found on the token.");

            // Asked without holding the module lock: the prompt waits for the user.
            var pin = pinPrompt($"Enter the PIN for token \"{tokenLabel}\"") ?? throw new OperationCanceledException("PIN entry was cancelled.");
            lock (_gate)
            {
                Login(session, pin);
                var key = FindPrivateKey(session, cert, ckaId)
                    ?? throw new SignerException("The private key for the certificate was not found on the token.");
                var alwaysAuthenticate = ReadBool(session, key, CKA.CKA_ALWAYS_AUTHENTICATE);
                return new Pkcs11Identity(this, session, key, cert, extra, alwaysAuthenticate);
            }
        }
        catch
        {
            lock (_gate) session.Dispose();
            throw;
        }
    }

    private static void Login(ISession session, string pin)
    {
        try
        {
            session.Login(CKU.CKU_USER, pin);
        }
        catch (Pkcs11Exception ex) when (ex.RV == CKR.CKR_USER_ALREADY_LOGGED_IN)
        {
        }
        catch (Pkcs11Exception ex) when (ex.RV is CKR.CKR_PIN_INCORRECT or CKR.CKR_PIN_INVALID or CKR.CKR_PIN_LEN_RANGE)
        {
            throw new SignerException("Wrong PIN. Note: the token locks after too many wrong attempts.", ex);
        }
        catch (Pkcs11Exception ex) when (ex.RV == CKR.CKR_PIN_LOCKED)
        {
            throw new SignerException("The token PIN is locked. Unlock it with SafeNet Authentication Client.", ex);
        }
    }

    private static bool ReadBool(ISession session, IObjectHandle handle, CKA attribute)
    {
        try
        {
            var value = session.GetAttributeValue(handle, [attribute])[0];
            return !value.CannotBeRead && value.GetValueAsBool();
        }
        catch (Pkcs11Exception)
        {
            return false;
        }
    }

    private static List<(X509Certificate2 Cert, byte[] CkaId)> FindCertificates(ISession session)
    {
        var search = new List<IObjectAttribute>
        {
            Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
            Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
        };
        var result = new List<(X509Certificate2, byte[])>();
        foreach (var handle in session.FindAllObjects(search))
        {
            var attrs = session.GetAttributeValue(handle, [CKA.CKA_VALUE, CKA.CKA_ID]);
            var der = attrs[0].GetValueAsByteArray();
            if (der is null || der.Length == 0) continue;
            result.Add((X509CertificateLoader.LoadCertificate(der), attrs[1].GetValueAsByteArray() ?? []));
        }
        return result;
    }

    private static IObjectHandle? FindPrivateKey(ISession session, X509Certificate2 cert, byte[] ckaId)
    {
        var keyClass = Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        if (ckaId.Length > 0)
        {
            var byId = session.FindAllObjects([keyClass, Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId)]);
            if (byId.Count > 0) return byId[0];
        }
        // Fall back to matching the RSA modulus.
        using var rsa = cert.GetRSAPublicKey();
        if (rsa is null) return null;
        var modulus = rsa.ExportParameters(false).Modulus!;
        var byModulus = session.FindAllObjects([keyClass, Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS, modulus)]);
        return byModulus.FirstOrDefault();
    }

    public void Dispose() => _library.Dispose();

    private sealed class Pkcs11Identity(
        Pkcs11Module module, ISession session, IObjectHandle key, X509Certificate2 cert, List<X509Certificate2> extra, bool alwaysAuthenticate)
        : ISigningIdentity, IDisposable
    {
        // DER DigestInfo prefix for SHA-1; CKM_RSA_PKCS works on tokens that do not hash on-card.
        private static readonly byte[] Sha1DigestInfo = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];

        public X509Certificate2 Certificate => cert;
        public IReadOnlyList<X509Certificate2> ExtraCertificates => extra;

        public byte[] SignSha1(byte[] data)
        {
            var digestInfo = Sha1DigestInfo.Concat(SHA1.HashData(data)).ToArray();
            lock (module._gate)
            {
                try
                {
                    using var mechanism = Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);
                    return session.Sign(mechanism, key, digestInfo);
                }
                catch (Pkcs11Exception ex) when (ex.RV == CKR.CKR_USER_NOT_LOGGED_IN && alwaysAuthenticate)
                {
                    // CKA_ALWAYS_AUTHENTICATE keys need a context-specific login between C_SignInit and C_Sign,
                    // which the single-call high-level Sign cannot do. Fail with the real reason instead of retrying.
                    throw new SignerException(
                        "This token key requires the PIN for every signature, which the PKCS#11 mode does not support yet. " +
                        (OperatingSystem.IsWindows() ? "Use the Windows certificate store mode instead (Settings)." : "Please report this."), ex);
                }
                catch (Pkcs11Exception ex) when (ex.RV is CKR.CKR_SESSION_HANDLE_INVALID or CKR.CKR_SESSION_CLOSED or CKR.CKR_DEVICE_REMOVED
                                                     or CKR.CKR_TOKEN_NOT_PRESENT or CKR.CKR_USER_NOT_LOGGED_IN or CKR.CKR_OBJECT_HANDLE_INVALID
                                                     or CKR.CKR_KEY_HANDLE_INVALID)
                {
                    throw new IdentityLostException("The token was removed or its session expired.", ex);
                }
            }
        }

        public void Dispose()
        {
            lock (module._gate)
            {
                try { session.Logout(); } catch (Pkcs11Exception) { }
                session.Dispose();
            }
        }
    }
}

/// <summary>The identity can no longer be used (token pulled, session closed); open it again.</summary>
public sealed class IdentityLostException(string message, Exception inner) : SignerException(message, inner);
