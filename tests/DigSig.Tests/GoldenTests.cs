using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.Json;
using System.Xml;
using DigSig.Core;
using DigSig.Core.Keys;

namespace DigSig.Tests;

/// <summary>
/// Compares against output captured from the original Java signer using the same test keys.
/// RSA PKCS#1 v1.5 is deterministic, so a correct port must reproduce the responses byte for byte.
/// </summary>
public class GoldenTests
{
    internal static string Data(params string[] parts) => Path.Combine([AppContext.BaseDirectory, "TestData", .. parts]);

    internal static PfxIdentity TestIdentity() => new(Data("test-leaf.pfx"), "test123");

    private static IEnumerable<string> InputNames() =>
        Directory.GetFiles(Data("in"), "*.xml").Select(f => Path.GetFileNameWithoutExtension(f)).Order();

    public static TheoryData<string> Inputs() => new(InputNames());

    [Theory]
    [MemberData(nameof(Inputs))]
    public void Signed_xml_matches_original_byte_for_byte(string name)
    {
        using var identity = TestIdentity();
        var input = File.ReadAllText(Data("in", name + ".xml"), new UTF8Encoding(false));

        var signed = XmlDsigSigner.Sign(input, identity);

        var expected = File.ReadAllText(Data("golden", name + ".signed.xml"), new UTF8Encoding(false));
        Assert.Equal(expected, signed);
    }

    // .NET's SignedXml also rejects the original's own output when the document contains CR characters
    // (04, 09); for those the byte-for-byte comparison above is the authoritative check.
    public static TheoryData<string> InputsWithoutCarriageReturns() =>
        new(InputNames().Where(n => n is not ("04-whitespace" or "09-attrs")));

    [Theory]
    [MemberData(nameof(InputsWithoutCarriageReturns))]
    public void Signed_xml_verifies_with_dotnet_signedxml(string name)
    {
        using var identity = TestIdentity();
        var signed = XmlDsigSigner.Sign(File.ReadAllText(Data("in", name + ".xml")), identity);

        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        doc.Load(XmlReader.Create(new StringReader(signed), new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = null }));
        var sx = new SignedXml(doc);
        sx.LoadXml((XmlElement)doc.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)[0]!);
        Assert.True(sx.CheckSignature(identity.Certificate, verifySignatureOnly: true));
    }

    [Theory]
    [InlineData("test-leaf.pfx", "golden")]
    [InlineData("kibs.pfx", "golden-kibs")]
    public void Certificate_json_matches_original(string pfx, string goldenDir)
    {
        using var identity = new PfxIdentity(Data(pfx), "test123");

        var json = CertificateDetails.From(identity).ToJson();

        using var expected = JsonDocument.Parse(File.ReadAllBytes(Data(goldenDir, "cert.json")));
        using var actual = JsonDocument.Parse(json);
        // Jackson's order of the derived properties varied between runs of the original, so compare by name.
        Assert.Equal(
            expected.RootElement.EnumerateObject().Select(p => (p.Name, p.Value.ToString())).OrderBy(p => p.Name),
            actual.RootElement.EnumerateObject().Select(p => (p.Name, p.Value.ToString())).OrderBy(p => p.Name));
    }

    [Fact]
    public void Subject_name_with_special_characters_matches_original_rfc2253()
    {
        using var identity = new PfxIdentity(Data("kibs.pfx"), "test123");
        var golden = File.ReadAllText(Data("golden-kibs", "01-basic.signed.xml"));
        var expected = new XmlDocument();
        expected.LoadXml(golden);

        Assert.Equal(expected.GetElementsByTagName("X509SubjectName")[0]!.InnerText, JavaDn.ToRfc2253(identity.Certificate.SubjectName));
    }

    [Fact]
    public void Pki_path_orders_trust_anchor_first()
    {
        using var identity = TestIdentity();
        var chain = CertificateDetails.BuildChain(identity.Certificate, identity.ExtraCertificates);

        Assert.Equal(3, chain.Count);
        Assert.Equal(identity.Certificate.Thumbprint, chain[0].Thumbprint);
        Assert.Equal(chain[^1].Subject, chain[^1].Issuer);
    }
}
