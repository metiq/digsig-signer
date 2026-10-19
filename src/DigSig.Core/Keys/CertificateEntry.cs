using System.Security.Cryptography.X509Certificates;

namespace DigSig.Core.Keys;

public enum CertificateSourceKind
{
    WindowsStore,
    Pkcs11Token,
    PfxFile,
}

/// <summary>A selectable signing certificate found in one of the sources.</summary>
/// <param name="Id">Stable identifier persisted in settings (e.g. "win:THUMBPRINT", "p11:TOKENSERIAL:THUMBPRINT").</param>
/// <param name="IsAvailable">False when the key lives on a token that is not plugged in.</param>
public sealed record CertificateEntry(
    string Id,
    X509Certificate2 Certificate,
    CertificateSourceKind Source,
    string SourceLabel,
    bool IsAvailable)
{
    public string CommonName => Certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
    public string IssuerName => Certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: true);

    /// <summary>Organization (O=) of the subject, i.e. the company the certificate signs for.</summary>
    public string? Organization => JavaDn.GetAttribute(Certificate.SubjectName, "2.5.4.10");

    /// <summary>Company VAT number exactly as the portal derives it.</summary>
    public string? CompanyVat
    {
        get
        {
            var subject = JavaDn.ToJavaString(Certificate.SubjectName);
            var issuer = JavaCertificateHelper.GetIssuerString(JavaDn.ToRfc2253(Certificate.IssuerName));
            return JavaCertificateHelper.GetCompanyVatNumber(subject, issuer);
        }
    }

    public bool IsExpired => Certificate.NotAfter < DateTime.Now;
}
