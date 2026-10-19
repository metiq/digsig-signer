using System.Text;
using System.Xml;

namespace DigSig.Core;

/// <summary>
/// Serializes a DOM the way the original signer did (JDK 8 Xalan identity transform on Windows), so the
/// portal receives byte-for-byte what it always has. The rules below were captured from the original app:
/// prolog with standalone="no", DOCTYPE dropped, namespace declarations first then attributes sorted by name,
/// redundant namespace declarations dropped, empty elements collapsed, LF in text and CDATA written as CRLF
/// (comments keep LF).
/// </summary>
public static class JavaXmlWriter
{
    private const string XmlnsNamespace = "http://www.w3.org/2000/xmlns/";
    private const string LineSeparator = "\r\n";

    public static string Write(XmlDocument doc)
    {
        var sb = new StringBuilder();
        var standaloneYes = doc.FirstChild is XmlDeclaration { Standalone: "yes" };
        sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"");
        if (!standaloneYes) sb.Append(" standalone=\"no\"");
        sb.Append("?>");

        var rootScope = new Dictionary<string, string> { [""] = "", ["xml"] = "http://www.w3.org/XML/1998/namespace" };
        foreach (XmlNode child in doc.ChildNodes)
        {
            switch (child.NodeType)
            {
                case XmlNodeType.Element:
                    WriteElement(sb, (XmlElement)child, rootScope);
                    break;
                case XmlNodeType.Comment:
                case XmlNodeType.ProcessingInstruction:
                    WriteNode(sb, child, rootScope);
                    break;
                // XmlDeclaration, DocumentType and whitespace between top-level nodes are not emitted.
            }
        }
        return sb.ToString();
    }

    private static void WriteNode(StringBuilder sb, XmlNode node, Dictionary<string, string> scope)
    {
        switch (node.NodeType)
        {
            case XmlNodeType.Element:
                WriteElement(sb, (XmlElement)node, scope);
                break;
            case XmlNodeType.Text:
            case XmlNodeType.Whitespace:
            case XmlNodeType.SignificantWhitespace:
                AppendEscapedText(sb, node.Value!);
                break;
            case XmlNodeType.CDATA:
                sb.Append("<![CDATA[").Append(node.Value!.Replace("\n", LineSeparator)).Append("]]>");
                break;
            case XmlNodeType.Comment:
                sb.Append("<!--").Append(node.Value).Append("-->");
                break;
            case XmlNodeType.ProcessingInstruction:
                var pi = (XmlProcessingInstruction)node;
                sb.Append("<?").Append(pi.Target);
                if (!string.IsNullOrEmpty(pi.Data)) sb.Append(' ').Append(pi.Data);
                sb.Append("?>");
                break;
            case XmlNodeType.EntityReference:
                foreach (XmlNode child in node.ChildNodes) WriteNode(sb, child, scope);
                break;
        }
    }

    private static void WriteElement(StringBuilder sb, XmlElement el, Dictionary<string, string> parentScope)
    {
        var scope = parentScope;
        var nsDecls = new List<(string Name, string Value)>();
        var attrs = new List<(string Name, string Value)>();

        void Declare(string prefix, string uri)
        {
            if (scope.TryGetValue(prefix, out var existing) && existing == uri) return;
            if (ReferenceEquals(scope, parentScope)) scope = new Dictionary<string, string>(parentScope);
            scope[prefix] = uri;
            nsDecls.Add((prefix.Length == 0 ? "xmlns" : "xmlns:" + prefix, uri));
        }

        foreach (XmlAttribute a in el.Attributes)
        {
            if (a.NamespaceURI == XmlnsNamespace)
                Declare(a.Prefix.Length == 0 ? "" : a.LocalName, a.Value);
            else
                attrs.Add((a.Name, a.Value));
        }
        // Namespace fixup for nodes created programmatically without an explicit xmlns attribute.
        Declare(el.Prefix, el.NamespaceURI);
        foreach (XmlAttribute a in el.Attributes)
        {
            if (a.NamespaceURI != XmlnsNamespace && a.Prefix.Length > 0 && a.Prefix != "xml")
                Declare(a.Prefix, a.NamespaceURI);
        }

        nsDecls.Sort((x, y) => string.CompareOrdinal(x.Name, y.Name));
        attrs.Sort((x, y) => string.CompareOrdinal(x.Name, y.Name));

        sb.Append('<').Append(el.Name);
        foreach (var (name, value) in nsDecls.Concat(attrs))
        {
            sb.Append(' ').Append(name).Append("=\"");
            AppendEscapedAttribute(sb, value);
            sb.Append('"');
        }

        if (!el.HasChildNodes)
        {
            sb.Append("/>");
            return;
        }
        sb.Append('>');
        foreach (XmlNode child in el.ChildNodes) WriteNode(sb, child, scope);
        sb.Append("</").Append(el.Name).Append('>');
    }

    private static void AppendEscapedText(StringBuilder sb, string text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            switch (c)
            {
                case '&': sb.Append("&amp;"); break;
                case '<': sb.Append("&lt;"); break;
                case '>': sb.Append("&gt;"); break;
                case '\r': sb.Append("&#13;"); break;
                case '\n': sb.Append(LineSeparator); break;
                default: i = AppendChar(sb, text, i); break;
            }
        }
    }

    private static void AppendEscapedAttribute(StringBuilder sb, string text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            switch (c)
            {
                case '&': sb.Append("&amp;"); break;
                case '<': sb.Append("&lt;"); break;
                case '>': sb.Append("&gt;"); break;
                case '"': sb.Append("&quot;"); break;
                case '\n': sb.Append("&#10;"); break;
                case '\r': sb.Append("&#13;"); break;
                case '\t': sb.Append("&#9;"); break;
                default: i = AppendChar(sb, text, i); break;
            }
        }
    }

    // C1 controls/DEL and supplementary characters become numeric references; everything else is written raw.
    private static int AppendChar(StringBuilder sb, string text, int i)
    {
        var c = text[i];
        if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
        {
            sb.Append("&#").Append(char.ConvertToUtf32(c, text[i + 1])).Append(';');
            return i + 1;
        }
        if (c is >= '\u007f' and <= '\u009f')
            sb.Append("&#").Append((int)c).Append(';');
        else
            sb.Append(c);
        return i;
    }
}
