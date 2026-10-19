using System.Text;
using DigSig.Core;
using DigSig.Core.Keys;
using DigSig.Core.Server;

// Headless companion to the desktop app: diagnostics, scripted signing, or running the server without a UI.
Console.OutputEncoding = Encoding.UTF8;
var options = Args.Parse(args);
if (options.Command is null or "help" || options.Has("help"))
{
    Console.WriteLine("""
        digsig-cli <command> [options]

        Commands:
          list                         List signing certificates and whether their token is plugged in
          serve                        Run the local HTTPS signer (https://localhost:8443) without the UI
          sign <in.xml> [out.xml]      Sign a file the same way the portal's requests are signed
          certificate                  Print the GET /certificate JSON for the selected certificate
          import-https-cert <jar>      Use the localhost HTTPS certificate of the original DigSig .jar

        Certificate selection (serve/sign/certificate):
          --cert <id>                  Id from 'list' (e.g. win:THUMBPRINT or p11:SERIAL:THUMBPRINT)
          --pfx <file> --password <p>  Use a .pfx/.p12 file instead
          --pkcs11 <library>           PKCS#11 library (default: SafeNet library if installed; on Windows only with this flag)
          --no-windows-store           Skip the Windows certificate store
          --port <n>                   Port for 'serve' (default 8443)
          --pin <pin>                  Token PIN (otherwise asked on the console)
        """);
    return 0;
}

using var provider = new SigningIdentityProvider(prompt =>
{
    if (options.Get("pin") is { } pin) return pin;
    Console.Error.Write(prompt + ": ");
    return ReadSecret();
})
{
    UseWindowsStore = OperatingSystem.IsWindows() && !options.Has("no-windows-store"),
    Pkcs11Library = options.Get("pkcs11") ?? (OperatingSystem.IsWindows() ? null : Pkcs11Module.FindDefaultLibrary()),
};

if (options.Get("pfx") is { } pfx)
{
    var entry = provider.Register(new PfxIdentity(pfx, options.Get("password") ?? ""), Path.GetFileName(pfx));
    provider.SelectedId = entry.Id;
}
else if (options.Get("cert") is { } certId)
{
    provider.SelectedId = certId;
}

try
{
    switch (options.Command)
    {
        case "list":
            var (entries, errors) = provider.ListCertificates();
            foreach (var e in entries)
            {
                var state = e.IsAvailable ? "ready" : "token not plugged in";
                Console.WriteLine($"{e.CommonName} — {e.Organization} (VAT {e.CompanyVat ?? "-"}), valid to {e.Certificate.NotAfter:d}, issuer {e.IssuerName}");
                Console.WriteLine($"    [{state}] {e.SourceLabel}");
                Console.WriteLine($"    --cert {e.Id}");
            }
            if (entries.Count == 0) Console.WriteLine("No signing certificates found.");
            foreach (var err in errors) Console.Error.WriteLine("warning: " + err);
            return 0;

        case "import-https-cert":
            var jar = options.Positional.ElementAtOrDefault(0) ?? throw new SignerException("Usage: import-https-cert <digsig-signer.jar>");
            using (var imported = HttpsCertificate.ImportFromOriginalJar(jar))
                Console.WriteLine($"Imported {imported.Subject} (valid to {imported.NotAfter:d}) to {HttpsCertificate.DefaultPath}");
            return 0;

        case "certificate":
            RequireSelection(provider);
            Console.WriteLine(Encoding.UTF8.GetString(provider.Use(CertificateDetails.From).ToJson()));
            return 0;

        case "sign":
            RequireSelection(provider);
            var input = options.Positional.ElementAtOrDefault(0) ?? throw new SignerException("Usage: sign <in.xml> [out.xml]");
            var signed = provider.Use(id => XmlDsigSigner.Sign(File.ReadAllText(input, Encoding.UTF8), id));
            if (options.Positional.ElementAtOrDefault(1) is { } output) File.WriteAllText(output, signed, new UTF8Encoding(false));
            else Console.WriteLine(signed);
            return 0;

        case "serve":
            RequireSelection(provider);
            var port = int.TryParse(options.Get("port"), out var p) ? p : SignerServerOptions.DefaultPort;
            await using (var server = new SignerServer(provider, new SignerServerOptions { Port = port }))
            {
                server.Activity += a => Console.WriteLine($"{a.Time:HH:mm:ss} {(a.Success ? "OK  " : "FAIL")} {a.Action} {a.Origin} — {a.Message} ({a.Duration.TotalMilliseconds:N0} ms)");
                await server.StartAsync();
                Console.WriteLine($"Listening on https://localhost:{port} — press Ctrl+C to stop.");
                var stop = new TaskCompletionSource();
                Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.TrySetResult(); };
                await stop.Task;
            }
            return 0;

        default:
            Console.Error.WriteLine($"Unknown command '{options.Command}'. Try 'help'.");
            return 2;
    }
}
catch (Exception ex) when (ex is SignerException or OperationCanceledException or IOException)
{
    Console.Error.WriteLine("error: " + ex.Message);
    return 1;
}

static void RequireSelection(SigningIdentityProvider provider)
{
    if (provider.SelectedId is not null) return;
    var available = provider.ListCertificates().Entries.Where(e => e.IsAvailable && !e.IsExpired).ToList();
    if (available.Count != 1)
        throw new SignerException(available.Count == 0
            ? "No usable certificate found (is the token plugged in?)."
            : "Several certificates are available; pick one with --cert <id> (see 'list').");
    provider.SelectedId = available[0].Id;
}

static string? ReadSecret()
{
    if (Console.IsInputRedirected) return Console.ReadLine();
    var sb = new StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) break;
        if (key.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; }
        else if (!char.IsControl(key.KeyChar)) sb.Append(key.KeyChar);
    }
    Console.Error.WriteLine();
    return sb.ToString();
}

sealed record Args(string? Command, List<string> Positional, Dictionary<string, string?> Named)
{
    public static Args Parse(string[] args)
    {
        var named = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var positional = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i].StartsWith("--"))
            {
                var name = args[i][2..];
                var hasValue = i + 1 < args.Length && !args[i + 1].StartsWith("--") && name is not ("help" or "no-windows-store");
                named[name] = hasValue ? args[++i] : null;
            }
            else positional.Add(args[i]);
        }
        return new Args(positional.FirstOrDefault(), positional.Skip(1).ToList(), named);
    }

    public bool Has(string name) => Named.ContainsKey(name);
    public string? Get(string name) => Named.GetValueOrDefault(name);
}
