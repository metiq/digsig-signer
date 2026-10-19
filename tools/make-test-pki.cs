// Generates the fictional test certificates used by tests/DigSig.Tests (dotnet run tools/make-test-pki.cs -- <outDir>).
// The identities are made up but shaped like real Macedonian qualified certificates, including the multi-valued
// RDNs and "COMPANY:VAT" / "VAT - n" fields the portal parses. Also writes application.properties files that point
// the original DigSig at each .pfx, for capturing golden output (see tools/capture-golden.sh).
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

var outDir = Path.GetFullPath(args.Length > 0 ? args[0] : ".");
Directory.CreateDirectory(outDir);
const string Password = "test123";

// --- Makedonski Telekom style: G + SN + SERIALNUMBER + CN in one RDN, VAT after ':' in OU -------------------------
var rootName = Dn(("2.5.4.6", "MK"), ("2.5.4.10", "DigSig Tests"), ("2.5.4.3", "DigSig Test Root CA"));
using var rootKey = RSA.Create(2048);
var rootReq = new CertificateRequest(rootName, rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
using var root = rootReq.CreateSelfSigned(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2045, 1, 1, 0, 0, 0, TimeSpan.Zero));

// The issuer name matters: the portal derives the VAT number differently per issuer organisation.
var caName = Dn(("2.5.4.6", "MK"), ("2.5.4.10", "Makedonski Telekom"), ("2.5.4.3", "Makedonski Telekom CA"));
using var caKey = RSA.Create(2048);
var caReq = new CertificateRequest(caName, caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
using var caPublic = caReq.Create(root, new DateTimeOffset(2020, 6, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2040, 1, 1, 0, 0, 0, TimeSpan.Zero), [0x40, 0x76, 0xCC, 0xB3]);
using var ca = caPublic.CopyWithPrivateKey(caKey);

var leafName = new X500DistinguishedName(EncodeName(
    [("2.5.4.6", "MK")],
    [("2.5.4.10", "PRIMER DOOEL"), ("2.5.4.97", "VATMK-4000000000001")],
    [("2.5.4.11", "PRIMER DOOEL:4000000000001")],
    [("2.5.4.42", "Petar"), ("2.5.4.4", "Petrovski"), ("2.5.4.5", "CRT0000001"), ("2.5.4.3", "Petar Petrovski")]));
using var leafKey = RSA.Create(2048);
var leafReq = new CertificateRequest(leafName, leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
using var leafPublic = leafReq.Create(ca, new DateTimeOffset(2025, 6, 24, 12, 50, 6, TimeSpan.Zero), new DateTimeOffset(2030, 6, 24, 13, 20, 6, TimeSpan.Zero),
    Convert.FromHexString("00C5A240A95BD9860880CC4A5AD0D5F919"));
using var leaf = leafPublic.CopyWithPrivateKey(leafKey);
WritePfx("test-leaf", leaf, caPublic, X509CertificateLoader.LoadCertificate(root.RawData));

// --- KIBS style with awkward characters: exercises Java's DN quoting/escaping rules -------------------------------
var kibsCaBuilder = new X500DistinguishedNameBuilder();
kibsCaBuilder.AddCountryOrRegion("MK");
kibsCaBuilder.AddOrganizationName("KIBS AD Skopje");
kibsCaBuilder.AddCommonName("KIBSTrust Qualified CA");
using var kibsCaKey = RSA.Create(2048);
var kibsCaReq = new CertificateRequest(kibsCaBuilder.Build(), kibsCaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
kibsCaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
using var kibsCa = kibsCaReq.CreateSelfSigned(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2040, 1, 1, 0, 0, 0, TimeSpan.Zero));

var b = new X500DistinguishedNameBuilder();
b.AddCountryOrRegion("MK");
b.AddLocalityName("Скопје");
b.Add("2.5.4.8", "Skopje, \"Centar\"", UniversalTagNumber.UTF8String);
b.Add("2.5.4.9", "Ул. Македонија 1 + 2; <x>", UniversalTagNumber.UTF8String);
b.AddOrganizationName("Пример ДООЕЛ");
b.AddOrganizationalUnitName("VAT - 4000000000002");
b.Add("2.5.4.12", "Manager", UniversalTagNumber.PrintableString);
b.Add("0.9.2342.19200300.100.1.25", "example", UniversalTagNumber.IA5String);
b.Add("0.9.2342.19200300.100.1.1", "uid123", UniversalTagNumber.UTF8String);
b.AddEmailAddress("petar@example.mk");
b.Add("2.5.4.5", "#123", UniversalTagNumber.UTF8String);
b.Add("2.5.4.43", "PP", UniversalTagNumber.UTF8String);
b.Add("2.5.4.46", "dnq", UniversalTagNumber.PrintableString);
b.Add("2.5.4.44", "Jr", UniversalTagNumber.UTF8String);
b.Add("1.2.3.4.5", "custom=val", UniversalTagNumber.UTF8String);
b.AddCommonName(" Петар  Петровски, \"Test\"" + '\\' + " ");
using var kibsKey = RSA.Create(2048);
var kibsReq = new CertificateRequest(b.Build(), kibsKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
using var kibsPublic = kibsReq.Create(kibsCa, new DateTimeOffset(2025, 12, 31, 23, 30, 0, TimeSpan.Zero), new DateTimeOffset(2027, 1, 1, 0, 30, 0, TimeSpan.Zero), [0x01, 0x02]);
using var kibs = kibsPublic.CopyWithPrivateKey(kibsKey);
WritePfx("kibs", kibs, X509CertificateLoader.LoadCertificate(kibsCa.RawData));

Console.WriteLine($"Wrote test-leaf.pfx and kibs.pfx (password {Password}) to {outDir}");

void WritePfx(string name, X509Certificate2 cert, params X509Certificate2[] chain)
{
    var collection = new X509Certificate2Collection(cert);
    collection.AddRange(chain);
    var pfx = Path.Combine(outDir, name + ".pfx");
    File.WriteAllBytes(pfx, collection.Export(X509ContentType.Pfx, Password)!);

    // The original stores the keystore passcode AES/ECB-encrypted with key SHA1("SPONGEBOBISGOD")[0..16].
    using var aes = Aes.Create();
    aes.Key = SHA1.HashData(Encoding.UTF8.GetBytes("SPONGEBOBISGOD"))[..16];
    var passcode = Convert.ToBase64String(aes.EncryptEcb(Encoding.UTF8.GetBytes(Password), PaddingMode.PKCS7));
    var dir = Path.Combine(outDir, name);
    Directory.CreateDirectory(dir);
    File.WriteAllText(Path.Combine(dir, "application.properties"),
        $"configuration.keystore.containerType=PFX\nconfiguration.keystore.location={pfx.Replace('\\', '/')}\nconfiguration.keystore.passcode={passcode}\n");
}

static X500DistinguishedName Dn(params (string Oid, string Value)[] rdns) =>
    new(EncodeName(rdns.Select(r => new[] { r }).ToArray()));

// Name ::= SEQUENCE OF SET OF AttributeTypeAndValue; each inner array is one (possibly multi-valued) RDN.
static byte[] EncodeName(params (string Oid, string Value)[][] rdns)
{
    var w = new AsnWriter(AsnEncodingRules.DER);
    using (w.PushSequence())
    {
        foreach (var rdn in rdns)
        {
            using (w.PushSetOf())
            {
                foreach (var (oid, value) in rdn)
                {
                    using (w.PushSequence())
                    {
                        w.WriteObjectIdentifier(oid);
                        w.WriteCharacterString(UniversalTagNumber.PrintableString, value);
                    }
                }
            }
        }
    }
    return w.Encode();
}
