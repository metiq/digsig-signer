using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using DigSig.Core.Keys;

namespace DigSig.Core;

/// <summary>
/// Produces the same enveloped XML-DSig as the original signer (cis.common.digsig XmlSignSinger):
/// inclusive C14N, RSA-SHA1, a single Reference URI="" with the enveloped-signature transform, SHA-1 digest,
/// and KeyInfo/X509Data with X509SubjectName (RFC 2253) followed by X509Certificate.
/// </summary>
public static class XmlDsigSigner
{
    private const string DsigNs = "http://www.w3.org/2000/09/xmldsig#";
    private const string XmlnsNs = "http://www.w3.org/2000/xmlns/";
    private const string XmlNs = "http://www.w3.org/XML/1998/namespace";

    public static string Sign(string xml, ISigningIdentity identity)
    {
        var doc = Load(xml);
        var root = doc.DocumentElement ?? throw new XmlException("The document has no root element.");

        // Reference URI="" + enveloped-signature: the whole document (no comments) before the signature is attached.
        var digest = SHA1.HashData(Canonicalize(doc));

        var signature = El(doc, "Signature");
        signature.Attributes.Append(XmlnsAttr(doc, DsigNs));
        var signedInfo = Append(signature, El(doc, "SignedInfo"));
        Append(signedInfo, El(doc, "CanonicalizationMethod", ("Algorithm", SignedXml.XmlDsigC14NTransformUrl)));
        Append(signedInfo, El(doc, "SignatureMethod", ("Algorithm", SignedXml.XmlDsigRSASHA1Url)));
        var reference = Append(signedInfo, El(doc, "Reference", ("URI", "")));
        var transforms = Append(reference, El(doc, "Transforms"));
        Append(transforms, El(doc, "Transform", ("Algorithm", SignedXml.XmlDsigEnvelopedSignatureTransformUrl)));
        Append(reference, El(doc, "DigestMethod", ("Algorithm", SignedXml.XmlDsigSHA1Url)));
        Append(reference, El(doc, "DigestValue")).InnerText = Convert.ToBase64String(digest);
        var signatureValue = Append(signature, El(doc, "SignatureValue"));
        var x509Data = Append(Append(signature, El(doc, "KeyInfo")), El(doc, "X509Data"));
        Append(x509Data, El(doc, "X509SubjectName")).InnerText = JavaDn.ToRfc2253(identity.Certificate.SubjectName);
        Append(x509Data, El(doc, "X509Certificate")).InnerText = WrapBase64(identity.Certificate.RawData);
        root.AppendChild(signature);

        var signedInfoBytes = CanonicalizeInContext(signedInfo);
        signatureValue.InnerText = WrapBase64(identity.SignSha1(signedInfoBytes));

        return JavaXmlWriter.Write(doc);
    }

    /// <summary>Parses like Java's DocumentBuilder: the body is treated as UTF-8 text, entities are expanded, nothing is fetched.</summary>
    internal static XmlDocument Load(string xml)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Parse,
            XmlResolver = null,
            MaxCharactersFromEntities = 10_000_000,
            IgnoreWhitespace = false,
        };
        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(xml));
        using var reader = XmlReader.Create(stream, settings);
        doc.Load(reader);
        return doc;
    }

    // Hash the canonical stream ourselves: XmlDsigC14NTransform.GetDigestedOutput disagrees with its own
    // GetOutput (and with Java) when there are processing instructions/comments outside the root element.
    private static byte[] Canonicalize(XmlDocument doc)
    {
        var t = new XmlDsigC14NTransform(includeComments: false);
        t.LoadInput(doc);
        using var output = (Stream)t.GetOutput(typeof(Stream));
        using var ms = new MemoryStream();
        output.CopyTo(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Inclusive C14N of SignedInfo as a document subset: the apex element carries every namespace declaration
    /// in scope and the xml:* attributes (xml:lang, xml:space, ...) inherited from its ancestors, like Java signs it.
    /// </summary>
    private static byte[] CanonicalizeInContext(XmlElement element)
    {
        var namespaces = new Dictionary<string, string>();
        var xmlAttrs = new Dictionary<string, string>();
        for (var node = element as XmlNode; node is XmlElement e; node = e.ParentNode)
        {
            foreach (XmlAttribute a in e.Attributes)
            {
                if (a.NamespaceURI == XmlnsNs)
                    namespaces.TryAdd(a.Prefix.Length == 0 ? "" : a.LocalName, a.Value);
                else if (a.NamespaceURI == XmlNs)
                    xmlAttrs.TryAdd(a.LocalName, a.Value);
            }
        }

        var subset = new XmlDocument { PreserveWhitespace = true };
        var apex = (XmlElement)subset.ImportNode(element, deep: true);
        subset.AppendChild(apex);
        foreach (var (prefix, uri) in namespaces)
        {
            if (prefix.Length == 0 && uri.Length == 0) continue;
            var name = prefix.Length == 0 ? "xmlns" : "xmlns:" + prefix;
            if (!apex.HasAttribute(name)) apex.SetAttributeNode(XmlnsAttr(subset, uri, prefix));
        }
        foreach (var (localName, value) in xmlAttrs)
        {
            if (apex.HasAttribute(localName, XmlNs)) continue;
            var attr = subset.CreateAttribute("xml", localName, XmlNs);
            attr.Value = value;
            apex.SetAttributeNode(attr);
        }
        return Canonicalize(subset);
    }

    // Java's XML-DSig (Santuario) wraps base64 at 76 characters with CRLF.
    internal static string WrapBase64(byte[] data)
    {
        var b64 = Convert.ToBase64String(data);
        var sb = new StringBuilder(b64.Length + b64.Length / 76 * 2);
        for (var i = 0; i < b64.Length; i += 76)
        {
            if (i > 0) sb.Append("\r\n");
            sb.Append(b64, i, Math.Min(76, b64.Length - i));
        }
        return sb.ToString();
    }

    private static XmlElement El(XmlDocument doc, string name, params (string Name, string Value)[] attrs)
    {
        var el = doc.CreateElement(name, DsigNs);
        foreach (var (n, v) in attrs) el.SetAttribute(n, v);
        return el;
    }

    private static XmlElement Append(XmlElement parent, XmlElement child)
    {
        parent.AppendChild(child);
        return child;
    }

    private static XmlAttribute XmlnsAttr(XmlDocument doc, string uri, string prefix = "")
    {
        var attr = prefix.Length == 0 ? doc.CreateAttribute("xmlns", XmlnsNs) : doc.CreateAttribute("xmlns", prefix, XmlnsNs);
        attr.Value = uri;
        return attr;
    }
}
