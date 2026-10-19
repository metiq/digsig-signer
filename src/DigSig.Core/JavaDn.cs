using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DigSig.Core;

/// <summary>
/// Renders X.500 names exactly like Java 8 does, because the CDEPS portal receives (and parses) those strings:
/// <see cref="ToJavaString"/> mirrors <c>X509Certificate.getSubjectDN().getName()</c> (sun.security.x509.X500Name.toString)
/// and <see cref="ToRfc2253"/> mirrors <c>X500Principal.getName()</c>.
/// </summary>
public static class JavaDn
{
    // sun.security.x509.AVAKeyword, as resolved for the DEFAULT style (later registrations win, e.g. ST over S).
    private static readonly Dictionary<string, string> DefaultKeywords = new()
    {
        ["2.5.4.3"] = "CN",
        ["2.5.4.6"] = "C",
        ["2.5.4.7"] = "L",
        ["2.5.4.8"] = "ST",
        ["2.5.4.10"] = "O",
        ["2.5.4.11"] = "OU",
        ["2.5.4.12"] = "T",
        ["1.3.6.1.4.1.42.2.11.2.1"] = "IP",
        ["2.5.4.9"] = "STREET",
        ["0.9.2342.19200300.100.1.25"] = "DC",
        ["2.5.4.46"] = "DNQ",
        ["2.5.4.4"] = "SURNAME",
        ["2.5.4.42"] = "GIVENNAME",
        ["2.5.4.43"] = "INITIALS",
        ["2.5.4.44"] = "GENERATION",
        ["1.2.840.113549.1.9.1"] = "EMAILADDRESS",
        ["0.9.2342.19200300.100.1.1"] = "UID",
        ["2.5.4.5"] = "SERIALNUMBER",
    };

    // Keywords Java considers RFC 2253 compliant; everything else is printed as a dotted OID with a hex value.
    private static readonly Dictionary<string, string> Rfc2253Keywords = new()
    {
        ["2.5.4.3"] = "CN",
        ["2.5.4.6"] = "C",
        ["2.5.4.7"] = "L",
        ["2.5.4.8"] = "ST",
        ["2.5.4.10"] = "O",
        ["2.5.4.11"] = "OU",
        ["2.5.4.9"] = "STREET",
        ["0.9.2342.19200300.100.1.25"] = "DC",
        ["0.9.2342.19200300.100.1.1"] = "UID",
    };

    private const string SpecialChars1779 = ",=\n+<>#;\\\"";
    private const string SpecialChars2253 = ",=+<>#;\\\"";

    private sealed record Ava(string Oid, ReadOnlyMemory<byte> Encoded, Asn1Tag Tag, ReadOnlyMemory<byte> Content);

    public static string ToJavaString(X500DistinguishedName name) =>
        string.Join(", ", ParseRdns(name).AsEnumerable().Reverse().Select(rdn => string.Join(" + ", rdn.Select(AvaToKeywordValueString))));

    public static string ToRfc2253(X500DistinguishedName name) =>
        string.Join(",", ParseRdns(name).AsEnumerable().Reverse().Select(rdn => string.Join("+", rdn.Select(AvaToRfc2253String))));

    /// <summary>First string value of an attribute (e.g. "2.5.4.10" for O), also inside multi-valued RDNs.</summary>
    public static string? GetAttribute(X500DistinguishedName name, string oid) =>
        ParseRdns(name).SelectMany(rdn => rdn).Where(a => a.Oid == oid).Select(GetAsString).FirstOrDefault(v => v is not null);

    private static List<List<Ava>> ParseRdns(X500DistinguishedName name)
    {
        var result = new List<List<Ava>>();
        var reader = new AsnReader(name.RawData, AsnEncodingRules.BER);
        var seq = reader.ReadSequence();
        while (seq.HasData)
        {
            var set = seq.ReadSetOf(skipSortOrderValidation: true);
            var rdn = new List<Ava>();
            while (set.HasData)
            {
                var avaSeq = set.ReadSequence();
                var oid = avaSeq.ReadObjectIdentifier();
                var encoded = avaSeq.ReadEncodedValue();
                var tag = Asn1Tag.Decode(encoded.Span, out _);
                AsnDecoder.ReadEncodedValue(encoded.Span, AsnEncodingRules.BER, out var contentOffset, out var contentLength, out _);
                rdn.Add(new Ava(oid, encoded, tag, encoded.Slice(contentOffset, contentLength)));
            }
            result.Add(rdn);
        }
        return result;
    }

    // DerValue.getAsString(): null for non-string types.
    private static string? GetAsString(Ava ava)
    {
        if (ava.Tag.TagClass != TagClass.Universal) return null;
        var bytes = ava.Content.Span;
        return (UniversalTagNumber)ava.Tag.TagValue switch
        {
            UniversalTagNumber.UTF8String => Encoding.UTF8.GetString(bytes),
            UniversalTagNumber.PrintableString or UniversalTagNumber.IA5String or UniversalTagNumber.GeneralString => Encoding.ASCII.GetString(bytes),
            UniversalTagNumber.T61String => Encoding.Latin1.GetString(bytes),
            UniversalTagNumber.BMPString => Encoding.BigEndianUnicode.GetString(bytes),
            UniversalTagNumber.UniversalString => new UTF32Encoding(bigEndian: true, byteOrderMark: false).GetString(bytes),
            _ => null,
        };
    }

    // AVA.isDerString(value, canonical: false)
    private static bool IsDerString(Ava ava) =>
        ava.Tag.TagClass == TagClass.Universal && (UniversalTagNumber)ava.Tag.TagValue is
            UniversalTagNumber.PrintableString or UniversalTagNumber.T61String or UniversalTagNumber.IA5String or
            UniversalTagNumber.GeneralString or UniversalTagNumber.BMPString or UniversalTagNumber.UTF8String;

    private static string Hex(Ava ava) => "#" + Convert.ToHexStringLower(ava.Encoded.Span);

    // DerValue.isPrintableStringChar
    private static bool IsPrintableStringChar(char c) =>
        c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9'
            or ' ' or '\'' or '(' or ')' or '+' or ',' or '-' or '.' or '/' or ':' or '=' or '?';

    // AVA.toKeywordValueString (RFC 1779-ish quoting used by X500Name.toString)
    private static string AvaToKeywordValueString(Ava ava)
    {
        var keyword = DefaultKeywords.TryGetValue(ava.Oid, out var k) ? k : "OID." + ava.Oid;
        var valStr = GetAsString(ava);
        if (valStr is null) return keyword + "=" + Hex(ava);

        var sb = new StringBuilder();
        var quoteNeeded = false;
        var isPrevSpace = false;
        var length = valStr.Length;
        var alreadyQuoted = length > 1 && valStr[0] == '"' && valStr[length - 1] == '"';
        for (var i = 0; i < length; i++)
        {
            var c = valStr[i];
            if (alreadyQuoted && (i == 0 || i == length - 1))
            {
                sb.Append(c);
                continue;
            }
            if (IsPrintableStringChar(c) || SpecialChars1779.Contains(c))
            {
                if (!quoteNeeded && ((i == 0 && (c == ' ' || c == '\n')) || SpecialChars1779.Contains(c)))
                    quoteNeeded = true;
                if (c != ' ' && c != '\n')
                {
                    if (c == '"' || c == '\\') sb.Append('\\');
                    isPrevSpace = false;
                }
                else
                {
                    if (!quoteNeeded && isPrevSpace) quoteNeeded = true;
                    isPrevSpace = true;
                }
                sb.Append(c);
            }
            else
            {
                isPrevSpace = false;
                sb.Append(c);
            }
        }
        if (sb.Length > 0 && sb[^1] is ' ' or '\n') quoteNeeded = true;

        var value = sb.ToString();
        return keyword + "=" + (!alreadyQuoted && quoteNeeded ? "\"" + value + "\"" : value);
    }

    // AVA.toRFC2253String (non-canonical)
    private static string AvaToRfc2253String(Ava ava)
    {
        var keyword = Rfc2253Keywords.TryGetValue(ava.Oid, out var k) ? k : ava.Oid;
        if (char.IsAsciiDigit(keyword[0]) || !IsDerString(ava)) return keyword + "=" + Hex(ava);

        // Java decodes the raw content as UTF-8 here regardless of the string type.
        var valStr = Encoding.UTF8.GetString(ava.Content.Span);
        var escaped = new StringBuilder();
        foreach (var c in valStr)
        {
            if (IsPrintableStringChar(c) || SpecialChars2253.Contains(c))
            {
                if (SpecialChars2253.Contains(c)) escaped.Append('\\');
                escaped.Append(c);
            }
            else if (c == '\0') escaped.Append("\\00");
            else escaped.Append(c);
        }

        var chars = escaped.ToString();
        int lead = 0, trail = chars.Length - 1;
        while (lead < chars.Length && chars[lead] is ' ' or '\r') lead++;
        while (trail >= 0 && chars[trail] is ' ' or '\r') trail--;
        var sb = new StringBuilder(keyword).Append('=');
        for (var i = 0; i < chars.Length; i++)
        {
            if (i < lead || i > trail) sb.Append('\\');
            sb.Append(chars[i]);
        }
        return sb.ToString();
    }
}
