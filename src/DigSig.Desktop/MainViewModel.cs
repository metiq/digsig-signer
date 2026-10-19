using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using Avalonia.Threading;
using DigSig.Core;
using DigSig.Core.Keys;
using DigSig.Core.Server;

namespace DigSig.Desktop;

public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void Raise([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        Raise(name);
        return true;
    }
}

public sealed class CertificateItem(CertificateEntry entry) : ObservableObject
{
    private bool _isActive;

    public CertificateEntry Entry { get; } = entry;
    public string Title => Entry.Organization is { } org ? $"{Entry.CommonName} · {org}" : Entry.CommonName;
    public string Details => string.Join("  ·  ", new[]
    {
        Entry.CompanyVat is { } vat ? "VAT " + vat : null,
        Entry.IssuerName,
        "valid to " + Entry.Certificate.NotAfter.ToString("d"),
    }.Where(s => s is not null));
    public string Source => Entry.SourceLabel;
    public bool IsUsable => Entry.IsAvailable && !Entry.IsExpired;
    public string Availability => Entry.IsExpired ? "Expired" : Entry.IsAvailable ? "Ready" : "Token not plugged in";

    public bool IsActive
    {
        get => _isActive;
        set => Set(ref _isActive, value);
    }
}

public sealed record ActivityItem(string Time, bool Success, string Title, string Message, string? Origin, string Duration)
{
    public string Glyph => Success ? "✓" : "✕";
}

public sealed class MainViewModel : ObservableObject, IAsyncDisposable
{
    private const string SampleXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Test><Purpose>DigSig self-test</Purpose></Test>";

    private readonly AppSettings _settings;
    private readonly SigningIdentityProvider _provider;
    private SignerServer? _server;
    private string _serverStatus = "Starting…";
    private bool _isServerRunning;
    private string? _warning;
    private bool _isBusy;
    private string _allowedOriginsText;
    private X509Certificate2? _httpsCertificate;

    public MainViewModel(AppSettings settings, Func<string, string?> secretPrompt)
    {
        _settings = settings;
        _allowedOriginsText = string.Join(", ", settings.AllowedOrigins);
        _provider = new SigningIdentityProvider(secretPrompt) { SelectedId = settings.SelectedCertificateId };
        ApplySourceSettings();
    }

    public ObservableCollection<CertificateItem> Certificates { get; } = [];
    public ObservableCollection<ActivityItem> Activity { get; } = [];

    /// <summary>Raised (on the UI thread) when the list or the active certificate changes.</summary>
    public event Action? CertificatesChanged;

    public string ServerStatus { get => _serverStatus; private set => Set(ref _serverStatus, value); }
    public bool IsServerRunning { get => _isServerRunning; private set => Set(ref _isServerRunning, value); }
    public string? Warning { get => _warning; private set { Set(ref _warning, value); Raise(nameof(HasWarning)); } }
    public bool HasWarning => !string.IsNullOrEmpty(Warning);
    public bool IsBusy { get => _isBusy; private set => Set(ref _isBusy, value); }
    public bool HasNoCertificates => Certificates.Count == 0;

    public CertificateItem? ActiveCertificate => Certificates.FirstOrDefault(c => c.IsActive);
    public string ActiveSummary => ActiveCertificate?.Title ?? "No certificate selected";

    public bool IsWindows => OperatingSystem.IsWindows();

    public string AppVersion { get; } = "v" + (typeof(MainViewModel).Assembly
        .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
        .OfType<System.Reflection.AssemblyInformationalVersionAttribute>().FirstOrDefault()?.InformationalVersion.Split('+')[0] ?? "dev");

    public bool UseWindowsStore
    {
        get => _settings.UseWindowsStore;
        set { _settings.UseWindowsStore = value; Raise(); SaveAndRefresh(); }
    }

    public bool UsePkcs11
    {
        get => _settings.UsePkcs11;
        set { _settings.UsePkcs11 = value; Raise(); SaveAndRefresh(); }
    }

    public string? Pkcs11Library
    {
        get => _settings.Pkcs11Library;
        set { _settings.Pkcs11Library = value; Raise(); SaveAndRefresh(); }
    }

    public bool StartMinimized
    {
        get => _settings.StartMinimized;
        set { _settings.StartMinimized = value; Raise(); _settings.Save(); }
    }

    public bool CloseToTray
    {
        get => _settings.CloseToTray;
        set { _settings.CloseToTray = value; Raise(); _settings.Save(); }
    }

    public string Port
    {
        get => _settings.Port.ToString();
        set
        {
            if (int.TryParse(value, out var p) && p is > 0 and < 65536) _settings.Port = p;
            Raise();
        }
    }

    public string AllowedOriginsText
    {
        get => _allowedOriginsText;
        set => Set(ref _allowedOriginsText, value);
    }

    public string HttpsCertificateInfo
    {
        get
        {
            if (_httpsCertificate is not { } cert) return "Not loaded";
            var name = cert.GetNameInfo(X509NameType.SimpleName, false);
            var trust = !OperatingSystem.IsWindows() ? "" :
                HttpsCertificate.IsTrustedInWindows(cert) ? " · trusted by Windows" : " · not trusted by Windows yet";
            return $"{name} · valid to {cert.NotAfter:d}{trust}";
        }
    }

    public void TrustHttpsCertificate()
    {
        if (_httpsCertificate is null || !OperatingSystem.IsWindows()) return;
        try
        {
            HttpsCertificate.TrustInWindows(_httpsCertificate); // Windows shows its own confirmation
            Raise(nameof(HttpsCertificateInfo));
        }
        catch (Exception ex)
        {
            AddActivity(new ActivityEntry(DateTime.Now, "Trust HTTPS certificate", null, false, ex.Message, TimeSpan.Zero));
        }
    }

    public async Task ImportHttpsCertificateAsync(string jarPath)
    {
        try
        {
            var imported = await Task.Run(() => HttpsCertificate.ImportFromOriginalJar(jarPath));
            _httpsCertificate?.Dispose();
            _httpsCertificate = imported;
            Raise(nameof(HttpsCertificateInfo));
            AddActivity(new ActivityEntry(DateTime.Now, "HTTPS certificate imported", null, true,
                "Using the certificate of the original DigSig; browsers that trusted it keep working.", TimeSpan.Zero));
            await StartServerAsync();
        }
        catch (Exception ex)
        {
            AddActivity(new ActivityEntry(DateTime.Now, "Import HTTPS certificate", null, false, ex.Message, TimeSpan.Zero));
        }
    }

    public async Task StartAsync()
    {
        await StartServerAsync();
        await RefreshAsync();
    }

    public async Task ApplyServerSettingsAsync()
    {
        _settings.AllowedOrigins = AllowedOriginsText
            .Split([',', ' ', ';', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(o => o.TrimEnd('/'))
            .ToList();
        _settings.Save();
        await StartServerAsync();
    }

    private async Task StartServerAsync()
    {
        if (_server is not null) await _server.DisposeAsync();
        _server = null;
        IsServerRunning = false;
        try
        {
            _httpsCertificate ??= await Task.Run(() => HttpsCertificate.LoadOrCreate());
            Raise(nameof(HttpsCertificateInfo));
        }
        catch (Exception ex)
        {
            ServerStatus = "Not running: could not load the HTTPS certificate: " + ex.Message;
            return;
        }
        var server = new SignerServer(_provider, new SignerServerOptions
        {
            Port = _settings.Port,
            AllowedOrigins = _settings.AllowedOrigins,
            HttpsCertificate = _httpsCertificate,
        });
        server.Activity += a => Dispatcher.UIThread.Post(() => AddActivity(a));
        try
        {
            await server.StartAsync();
            _server = server;
            IsServerRunning = true;
            ServerStatus = $"Running on https://localhost:{_settings.Port}";
        }
        catch (Exception ex)
        {
            await server.DisposeAsync();
            ServerStatus = "Not running: " + ex.Message;
        }
    }

    public async Task RefreshAsync()
    {
        IsBusy = true;
        try
        {
            var (entries, errors) = await Task.Run(_provider.ListCertificates);
            Certificates.Clear();
            var ordered = entries
                .OrderByDescending(e => e.IsAvailable && !e.IsExpired)
                .ThenByDescending(e => e.CompanyVat is not null) // company certificates (Makedonski Telekom / KIBS) on top
                .ThenBy(e => e.CommonName, StringComparer.CurrentCultureIgnoreCase)
                .ThenBy(e => e.Organization, StringComparer.CurrentCultureIgnoreCase);
            foreach (var entry in ordered)
                Certificates.Add(new CertificateItem(entry) { IsActive = entry.Id == _provider.SelectedId });

            // First run (or the remembered certificate is gone): pick the only usable one automatically.
            if (ActiveCertificate is null && Certificates.Count(c => c.IsUsable) == 1)
                Activate(Certificates.First(c => c.IsUsable));

            Warning = errors.Count > 0 ? string.Join(Environment.NewLine, errors) : null;
            Raise(nameof(HasNoCertificates));
            RaiseActiveChanged();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public void Activate(CertificateItem item)
    {
        foreach (var c in Certificates) c.IsActive = ReferenceEquals(c, item);
        _provider.SelectedId = item.Entry.Id;
        if (item.Entry.Source != CertificateSourceKind.PfxFile)
        {
            _settings.SelectedCertificateId = item.Entry.Id;
            _settings.Save();
        }
        RaiseActiveChanged();
    }

    public void Activate(string id)
    {
        if (Certificates.FirstOrDefault(c => c.Entry.Id == id) is { } item) Activate(item);
    }

    public async Task TestSignatureAsync()
    {
        IsBusy = true;
        var started = DateTime.Now;
        try
        {
            var signed = await Task.Run(() => _provider.Use(identity => XmlDsigSigner.Sign(SampleXml, identity)));
            AddActivity(new ActivityEntry(started, "Test signature", null, true,
                $"Signed with {ActiveSummary} ({signed.Length:N0} chars).", DateTime.Now - started));
        }
        catch (Exception ex)
        {
            AddActivity(new ActivityEntry(started, "Test signature", null, false, ex.Message, DateTime.Now - started));
        }
        finally
        {
            IsBusy = false;
        }
    }

    public void Lock()
    {
        _provider.Lock();
        AddActivity(new ActivityEntry(DateTime.Now, "Locked", null, true, "The token session was closed; the PIN will be asked again.", TimeSpan.Zero));
    }

    public async Task AddPfxAsync(string path, string password)
    {
        try
        {
            var identity = await Task.Run(() => new PfxIdentity(path, password));
            var entry = _provider.Register(identity, Path.GetFileName(path));
            await RefreshAsync();
            Activate(entry.Id);
        }
        catch (Exception ex)
        {
            AddActivity(new ActivityEntry(DateTime.Now, "Open .pfx", null, false, ex.Message, TimeSpan.Zero));
        }
    }

    private void SaveAndRefresh()
    {
        _settings.Save();
        ApplySourceSettings();
        _ = RefreshAsync();
    }

    private void ApplySourceSettings()
    {
        _provider.UseWindowsStore = _settings.UseWindowsStore;
        _provider.Pkcs11Library = _settings.UsePkcs11 && !string.IsNullOrWhiteSpace(_settings.Pkcs11Library) ? _settings.Pkcs11Library : null;
    }

    private void AddActivity(ActivityEntry a)
    {
        Activity.Insert(0, new ActivityItem(a.Time.ToString("HH:mm:ss"), a.Success, a.Action, a.Message, a.Origin,
            a.Duration > TimeSpan.Zero ? $"{a.Duration.TotalMilliseconds:N0} ms" : ""));
        while (Activity.Count > 200) Activity.RemoveAt(Activity.Count - 1);
    }

    private void RaiseActiveChanged()
    {
        Raise(nameof(ActiveCertificate));
        Raise(nameof(ActiveSummary));
        CertificatesChanged?.Invoke();
    }

    public async ValueTask DisposeAsync()
    {
        if (_server is not null) await _server.DisposeAsync();
        _provider.Dispose();
    }
}
