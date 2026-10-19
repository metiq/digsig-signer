using System.Security.Cryptography.X509Certificates;
using DigSig.Core.Server;

namespace DigSig.Tests;

public class HttpsCertificateTests
{
    [Fact]
    public void Creates_a_localhost_certificate_once_and_reloads_it()
    {
        var path = Path.Combine(Path.GetTempPath(), "digsig-test-" + Guid.NewGuid().ToString("N"), "https.pfx");
        try
        {
            using var first = HttpsCertificate.LoadOrCreate(path);
            using var second = HttpsCertificate.LoadOrCreate(path);

            Assert.True(first.HasPrivateKey);
            Assert.Equal(first.Thumbprint, second.Thumbprint);
            Assert.True(first.MatchesHostname("localhost"));
            Assert.True(first.MatchesHostname("127.0.0.1"));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    // The original application is not in this repository; point DIGSIG_ORIGINAL_JAR at your copy to run this.
    [Fact]
    public void Imports_the_certificate_of_the_original_jar()
    {
        var jar = Environment.GetEnvironmentVariable("DIGSIG_ORIGINAL_JAR");
        Assert.SkipWhen(string.IsNullOrEmpty(jar) || !File.Exists(jar), "Set DIGSIG_ORIGINAL_JAR to digsig-signer-x.y.z.jar to run.");
        var path = Path.Combine(Path.GetTempPath(), "digsig-test-" + Guid.NewGuid().ToString("N"), "https.pfx");
        try
        {
            using var imported = HttpsCertificate.ImportFromOriginalJar(jar!, path);

            Assert.True(imported.HasPrivateKey);
            Assert.Contains("CN=CDEPS", imported.Subject);
            using var reloaded = HttpsCertificate.LoadOrCreate(path);
            Assert.Equal(imported.Thumbprint, reloaded.Thumbprint);
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }
}
