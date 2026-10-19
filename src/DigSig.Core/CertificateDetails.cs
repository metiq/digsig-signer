using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using System.Text.Json;
using DigSig.Core.Keys;

namespace DigSig.Core;

/// <summary>
/// The JSON returned by GET /certificate, field for field what Jackson produced from the original
/// CertificationChainDetails (including the derived subjectName / issuerString / companyVatNumber).
/// </summary>
public sealed record CertificateDetails(
    string CertificationChain,
    string SerialNumber,
    string Publisher,
    string ValidFrom,
    string ValidTo,
    string Subject,
    byte[] EncodedCertificate)
{
    public string? SubjectName => JavaCertificateHelper.GetSubjectName(Subject);
    public string? IssuerString => JavaCertificateHelper.GetIssuerString(Publisher);
    public string? CompanyVatNumber => JavaCertificateHelper.GetCompanyVatNumber(Subject, IssuerString);

    public static CertificateDetails From(ISigningIdentity identity)
    {
        var cert = identity.Certificate;
        var chain = BuildChain(cert, identity.ExtraCertificates);
        return new CertificateDetails(
            CertificationChain: Convert.ToBase64String(EncodePkiPath(chain)),
            SerialNumber: new BigInteger(cert.SerialNumberBytes.Span, isUnsigned: false, isBigEndian: true).ToString(),
            Publisher: JavaDn.ToRfc2253(cert.IssuerName),
            ValidFrom: JavaDate(cert.NotBefore),
            ValidTo: JavaDate(cert.NotAfter),
            Subject: JavaDn.ToJavaString(cert.SubjectName),
            EncodedCertificate: cert.RawData);
    }

    // DateFormat.getDateInstance(DateFormat.MEDIUM, new Locale("mk")) in the JVM's local time zone.
    private static string JavaDate(DateTime local) => $"{local.Day}.{local.Month}.{local.Year}";

    /// <summary>Leaf-first chain, like KeyStore.getCertificateChain().</summary>
    public static List<X509Certificate2> BuildChain(X509Certificate2 leaf, IEnumerable<X509Certificate2> extra)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.ExtraStore.AddRange(extra.ToArray());
        chain.Build(leaf);
        var result = chain.ChainElements.Select(e => e.Certificate).ToList();
        return result.Count > 0 ? result : [leaf];
    }

    /// <summary>CertPath.getEncoded("PkiPath"): SEQUENCE OF Certificate ordered from the trust anchor to the leaf.</summary>
    public static byte[] EncodePkiPath(IReadOnlyList<X509Certificate2> leafFirstChain)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            for (var i = leafFirstChain.Count - 1; i >= 0; i--) writer.WriteEncodedValue(leafFirstChain[i].RawData);
        }
        return writer.Encode();
    }

    private static readonly JsonWriterOptions JsonOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>Serializes with Jackson's property order and null for the unused "signature" field.</summary>
    public byte[] ToJson()
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms, JsonOptions))
        {
            w.WriteStartObject();
            w.WriteString("certificationChain", CertificationChain);
            w.WriteNull("signature");
            w.WriteString("serialNumber", SerialNumber);
            w.WriteString("publisher", Publisher);
            w.WriteString("validFrom", ValidFrom);
            w.WriteString("validTo", ValidTo);
            w.WriteString("subject", Subject);
            w.WriteBase64String("encodedCertificate", EncodedCertificate);
            WriteNullable(w, "subjectName", SubjectName);
            WriteNullable(w, "issuerString", IssuerString);
            WriteNullable(w, "companyVatNumber", CompanyVatNumber);
            w.WriteEndObject();
        }
        return ms.ToArray();
    }

    private static void WriteNullable(Utf8JsonWriter w, string name, string? value)
    {
        if (value is null) w.WriteNull(name);
        else w.WriteString(name, value);
    }
}

/// <summary>Faithful ports of cis.common.digsig.support.CertificateDataHelper / DefaultSubjectParser string logic.</summary>
public static class JavaCertificateHelper
{
    public static string? GetIssuerString(string? issuerDn) => Between(issuerDn, "O=", ",");

    public static string? GetSubjectName(string? subjectDn)
    {
        if (string.IsNullOrEmpty(subjectDn)) return null;
        var subject = Between(subjectDn, "CN=", ",")!;
        if (subject.Contains('+')) subject = Between(subject, null, "+")?.Trim();
        return subject;
    }

    public static string? GetCompanyVatNumber(string subject, string? issuer) => issuer switch
    {
        "KIBS AD Skopje" => Strip("OU=VAT - ", ",", subject) ?? Strip("SERIALNUMBER=", ",", subject),
        "Makedonski Telekom" => Strip(":", ",", subject),
        _ => null,
    };

    // CertificateDataHelper.getFromStringWithBegnAndEndString
    private static string? Between(string? input, string? begin, string end)
    {
        if (string.IsNullOrEmpty(input)) return null;
        var beginIndex = begin is null ? 0 : input.IndexOf(begin, StringComparison.Ordinal);
        var endIndex = input.IndexOf(end, Math.Max(beginIndex, 0), StringComparison.Ordinal);
        return beginIndex > -1 && endIndex > -1
            ? input[(beginIndex + (begin?.Length ?? 0))..endIndex]
            : input;
    }

    // AbstractCertificateSubjectParser.stripFromString
    private static string? Strip(string begin, string end, string subject)
    {
        var beginIndex = subject.IndexOf(begin, StringComparison.Ordinal);
        var endIndex = subject.IndexOf(end, Math.Max(beginIndex, 0), StringComparison.Ordinal);
        if (endIndex == -1) endIndex = subject.Length;
        return beginIndex > -1 ? subject[(beginIndex + begin.Length)..endIndex] : null;
    }
}
