using System.Net;
using System.Net.Sockets;
using System.Text;
using DigSig.Core.Keys;
using DigSig.Core.Server;

namespace DigSig.Tests;

/// <summary>HTTP behaviour compared with the headers/bodies captured from the original signer.</summary>
public sealed class ServerTests : IAsyncLifetime
{
    private readonly SigningIdentityProvider _provider = new(_ => null) { UseWindowsStore = false };
    private SignerServer _server = null!;
    private HttpClient _http = null!;
    private readonly List<ActivityEntry> _activity = [];

    public async ValueTask InitializeAsync()
    {
        _provider.SelectedId = _provider.Register(GoldenTests.TestIdentity(), "test").Id;
        var port = FreePort();
        _server = new SignerServer(_provider, new SignerServerOptions { Port = port, HttpsCertificate = HttpsCertificate.CreateSelfSigned() });
        _server.Activity += _activity.Add;
        await _server.StartAsync();
        _http = new HttpClient(new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true })
        {
            BaseAddress = new Uri($"https://localhost:{port}"),
        };
    }

    public async ValueTask DisposeAsync()
    {
        _http.Dispose();
        await _server.DisposeAsync();
        _provider.Dispose();
    }

    private static int FreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        return ((IPEndPoint)l.LocalEndpoint).Port;
    }

    [Fact]
    public async Task Signature_returns_201_with_the_originals_body_and_cors_headers()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/signature")
        {
            Content = new ByteArrayContent(File.ReadAllBytes(GoldenTests.Data("in", "02-cyrillic.xml"))),
        };
        request.Content.Headers.TryAddWithoutValidation("Content-Type", "application/xml");
        request.Headers.Add("Origin", "https://portal.example.mk");

        using var response = await _http.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("application/xml;charset=UTF-8", response.Content.Headers.ContentType!.ToString().Replace("; ", ";"));
        Assert.Equal("https://portal.example.mk", response.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.Equal("true", response.Headers.GetValues("Access-Control-Allow-Credentials").Single());
        Assert.Contains("Origin", response.Headers.Vary);
        Assert.Equal(File.ReadAllBytes(GoldenTests.Data("golden", "02-cyrillic.signed.xml")),
            await response.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken));
        Assert.Contains(_activity, a => a.Success && a.Action == "Sign declaration");
    }

    [Fact]
    public async Task Preflight_echoes_method_and_headers_like_spring_crossorigin()
    {
        var request = new HttpRequestMessage(HttpMethod.Options, "/signature");
        request.Headers.Add("Origin", "https://portal.example.mk");
        request.Headers.Add("Access-Control-Request-Method", "POST");
        request.Headers.Add("Access-Control-Request-Headers", "content-type, x-foo");
        request.Headers.Add("Access-Control-Request-Private-Network", "true");

        using var response = await _http.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("https://portal.example.mk", response.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.Equal("POST", response.Headers.GetValues("Access-Control-Allow-Methods").Single());
        Assert.Equal("content-type, x-foo", response.Headers.GetValues("Access-Control-Allow-Headers").Single());
        Assert.Equal("1800", response.Headers.GetValues("Access-Control-Max-Age").Single());
        Assert.Equal("true", response.Headers.GetValues("Access-Control-Allow-Private-Network").Single());
    }

    [Fact]
    public async Task Certificate_returns_json()
    {
        using var response = await _http.GetAsync("/certificate", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType!.MediaType);
        var json = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("\"companyVatNumber\":\"4000000000001\"", json);
    }

    [Fact]
    public async Task Non_xml_content_type_is_rejected_with_415()
    {
        using var response = await _http.PostAsync("/signature", new StringContent("<a/>", Encoding.UTF8, "text/plain"),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
    }

    [Fact]
    public async Task Invalid_xml_fails_with_a_readable_message()
    {
        using var response = await _http.PostAsync("/signature", new StringContent("not xml", Encoding.UTF8, "application/xml"),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Contains(_activity, a => !a.Success && a.Message.StartsWith("The document is not valid XML"));
    }
}
