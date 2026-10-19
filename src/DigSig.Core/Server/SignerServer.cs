using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Xml;
using DigSig.Core.Keys;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace DigSig.Core.Server;

public sealed record ActivityEntry(DateTime Time, string Action, string? Origin, bool Success, string Message, TimeSpan Duration);

public sealed class SignerServerOptions
{
    public const int DefaultPort = 8443;

    public int Port { get; set; } = DefaultPort;

    /// <summary>Origins allowed to call the signer. Empty = any origin (what the original did).</summary>
    public IReadOnlyCollection<string> AllowedOrigins { get; set; } = [];

    /// <summary>HTTPS certificate; null uses <see cref="Server.HttpsCertificate.LoadOrCreate"/>.</summary>
    public X509Certificate2? HttpsCertificate { get; set; }
}

/// <summary>
/// The local HTTPS API the CDEPS web portal calls, compatible with the original DigSig (digsig-signer 1.3.7):
/// GET /certificate → 200 JSON, POST /signature (application/xml) → 201 signed XML; CORS like Spring's @CrossOrigin.
/// </summary>
public sealed class SignerServer(SigningIdentityProvider identities, SignerServerOptions options) : IAsyncDisposable
{
    private WebApplication? _app;

    public event Action<ActivityEntry>? Activity;

    public async Task StartAsync()
    {
        var httpsCert = options.HttpsCertificate ?? HttpsCertificate.LoadOrCreate();
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseKestrelHttpsConfiguration();
        builder.WebHost.ConfigureKestrel(k =>
        {
            k.AddServerHeader = false;
            // Loopback only: the original listened on all interfaces, exposing signing to the local network.
            k.Listen(IPAddress.Loopback, options.Port, l => l.UseHttps(httpsCert));
            if (Socket.OSSupportsIPv6) k.Listen(IPAddress.IPv6Loopback, options.Port, l => l.UseHttps(httpsCert));
        });

        var app = builder.Build();
        app.Use(CorsMiddleware);
        app.MapGet("/", () => Results.Content(
            "<!doctype html><meta charset=utf-8><title>DigSig</title><p>DigSig is running. You can close this tab.</p>",
            "text/html; charset=utf-8"));
        app.MapGet("/certificate", (Delegate)GetCertificate);
        app.MapPost("/signature", (Delegate)CreateSignature);

        try
        {
            await app.StartAsync();
        }
        catch (IOException ex) when (ex.InnerException is AddressInUseException)
        {
            await app.DisposeAsync();
            throw new SignerException($"Port {options.Port} is already in use. Is the old Java signer (or another copy of this app) still running?", ex);
        }
        _app = app;
    }

    private async Task CorsMiddleware(HttpContext ctx, Func<Task> next)
    {
        var origin = ctx.Request.Headers.Origin.ToString();
        if (origin.Length > 0)
        {
            if (options.AllowedOrigins.Count > 0 && !options.AllowedOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase))
            {
                Report("Blocked request", origin, false, $"Origin {origin} is not in the allowed list.", TimeSpan.Zero);
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
            ctx.Response.Headers.AccessControlAllowOrigin = origin;
            ctx.Response.Headers.Vary = "Origin";
            ctx.Response.Headers.AccessControlAllowCredentials = "true";

            var preflightMethod = ctx.Request.Headers.AccessControlRequestMethod.ToString();
            if (HttpMethods.IsOptions(ctx.Request.Method) && preflightMethod.Length > 0)
            {
                ctx.Response.Headers.AccessControlAllowMethods = preflightMethod;
                var requestedHeaders = ctx.Request.Headers.AccessControlRequestHeaders.ToString();
                if (requestedHeaders.Length > 0) ctx.Response.Headers.AccessControlAllowHeaders = requestedHeaders;
                ctx.Response.Headers.AccessControlMaxAge = "1800";
                // Chrome's Private Network Access preflight for public sites calling localhost.
                if (ctx.Request.Headers["Access-Control-Request-Private-Network"] == "true")
                    ctx.Response.Headers["Access-Control-Allow-Private-Network"] = "true";
                if (ctx.Request.Headers["Access-Control-Request-Local-Network"] == "true")
                    ctx.Response.Headers["Access-Control-Allow-Local-Network"] = "true";
                ctx.Response.StatusCode = StatusCodes.Status200OK;
                return;
            }
        }
        await next();
    }

    private IResult GetCertificate(HttpContext ctx)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var details = identities.Use(CertificateDetails.From);
            Report("Certificate requested", Origin(ctx), true, details.SubjectName ?? details.Subject, sw.Elapsed);
            return Results.Bytes(details.ToJson(), "application/json;charset=UTF-8");
        }
        catch (Exception ex)
        {
            return Fail(ctx, "Certificate requested", ex, sw.Elapsed);
        }
    }

    private async Task<IResult> CreateSignature(HttpContext ctx)
    {
        var sw = Stopwatch.StartNew();
        var contentType = MediaTypeHeaderValue.TryParse(ctx.Request.ContentType, out var ct) ? ct : null;
        var mediaType = contentType?.MediaType.Value ?? "";
        if (!mediaType.Equals("application/xml", StringComparison.OrdinalIgnoreCase) &&
            !mediaType.Equals("text/xml", StringComparison.OrdinalIgnoreCase) &&
            !mediaType.EndsWith("+xml", StringComparison.OrdinalIgnoreCase))
        {
            Report("Sign declaration", Origin(ctx), false, $"Unsupported content type '{ctx.Request.ContentType}'.", sw.Elapsed);
            return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);
        }

        try
        {
            var encoding = contentType?.Encoding ?? Encoding.UTF8;
            using var reader = new StreamReader(ctx.Request.Body, encoding, detectEncodingFromByteOrderMarks: false);
            var payload = await reader.ReadToEndAsync(ctx.RequestAborted);

            var signed = await Task.Run(() => identities.Use(identity => XmlDsigSigner.Sign(payload, identity)), ctx.RequestAborted);
            Report("Sign declaration", Origin(ctx), true, DescribeDocument(payload), sw.Elapsed);
            // Written directly so the header reads exactly "application/xml;charset=UTF-8" like Spring's.
            ctx.Response.StatusCode = StatusCodes.Status201Created;
            ctx.Response.ContentType = "application/xml;charset=UTF-8";
            await ctx.Response.Body.WriteAsync(Encoding.UTF8.GetBytes(signed), ctx.RequestAborted);
            return Results.Empty;
        }
        catch (Exception ex)
        {
            return Fail(ctx, "Sign declaration", ex, sw.Elapsed);
        }
    }

    private IResult Fail(HttpContext ctx, string action, Exception ex, TimeSpan elapsed)
    {
        var message = ex switch
        {
            SignerException or OperationCanceledException => ex.Message,
            XmlException => "The document is not valid XML: " + ex.Message,
            _ => ex.GetType().Name + ": " + ex.Message,
        };
        Report(action, Origin(ctx), false, message, elapsed);
        var body = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            ["status"] = 500,
            ["error"] = "Internal Server Error",
            ["message"] = message,
            ["path"] = ctx.Request.Path.ToString(),
        });
        return Results.Text(body, "application/json;charset=UTF-8", Encoding.UTF8, StatusCodes.Status500InternalServerError);
    }

    private static string? Origin(HttpContext ctx) => ctx.Request.Headers.Origin is { Count: > 0 } o ? o.ToString() : null;

    private static string DescribeDocument(string payload)
    {
        try
        {
            using var reader = XmlReader.Create(new StringReader(payload), new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore });
            reader.MoveToContent();
            return $"<{reader.Name}> ({Encoding.UTF8.GetByteCount(payload):N0} bytes)";
        }
        catch (XmlException)
        {
            return $"{payload.Length:N0} chars";
        }
    }

    private void Report(string action, string? origin, bool success, string message, TimeSpan elapsed) =>
        Activity?.Invoke(new ActivityEntry(DateTime.Now, action, origin, success, message, elapsed));

    public async ValueTask DisposeAsync()
    {
        if (_app is not null) await _app.DisposeAsync();
        _app = null;
    }
}
