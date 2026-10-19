using System.Security.Cryptography.X509Certificates;

namespace DigSig.Core.Keys;

/// <summary>
/// Knows every certificate source, which certificate is selected, and keeps the opened identity
/// (logged-in token session) alive between signing requests.
/// </summary>
/// <remarks>
/// Opening an identity can block on a PIN prompt shown by the UI thread (or by Windows), so <c>_gate</c> is only
/// ever held for quick field swaps; the UI thread calls <see cref="SelectedId"/> and <see cref="Lock"/> and must
/// never wait behind a prompt. Token use itself is serialized by <c>_signing</c>.
/// </remarks>
public sealed class SigningIdentityProvider(Func<string, string?> secretPrompt) : IDisposable
{
    private readonly object _gate = new();
    private readonly SemaphoreSlim _signing = new(1, 1);
    private readonly Dictionary<string, Pkcs11Module> _modules = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (ISigningIdentity Identity, string Label)> _registered = new();
    private string? _selectedId;
    private ISigningIdentity? _cached;
    private string? _cachedId;

    /// <summary>Include certificates from the Windows store (Windows only).</summary>
    public bool UseWindowsStore { get; set; } = OperatingSystem.IsWindows();

    /// <summary>PKCS#11 library to scan for tokens, or null to skip.</summary>
    public string? Pkcs11Library { get; set; }

    /// <summary>Adds an already-unlocked identity (e.g. a .pfx opened with its password) for this session.</summary>
    public CertificateEntry Register(ISigningIdentity identity, string label)
    {
        var id = "mem:" + identity.Certificate.Thumbprint;
        lock (_gate) _registered[id] = (identity, label);
        return new CertificateEntry(id, identity.Certificate, CertificateSourceKind.PfxFile, label, IsAvailable: true);
    }

    public string? SelectedId
    {
        get { lock (_gate) return _selectedId; }
        set
        {
            lock (_gate)
            {
                if (_selectedId == value) return;
                _selectedId = value;
            }
            Lock();
        }
    }

    /// <summary>Lists certificates from all configured sources. Never opens a private key, so it never prompts.</summary>
    public (List<CertificateEntry> Entries, List<string> Errors) ListCertificates()
    {
        var entries = new List<CertificateEntry>();
        var errors = new List<string>();
        if (UseWindowsStore && OperatingSystem.IsWindows())
        {
            try { entries.AddRange(WindowsStoreSource.List()); }
            catch (Exception ex) { errors.Add("Windows certificate store: " + ex.Message); }
        }
        if (Pkcs11Library is { Length: > 0 } library)
        {
            try { entries.AddRange(GetModule(library).List()); }
            catch (Exception ex) { errors.Add("PKCS#11: " + ex.Message); }
        }
        lock (_gate)
        {
            entries.AddRange(_registered.Select(r =>
                new CertificateEntry(r.Key, r.Value.Identity.Certificate, CertificateSourceKind.PfxFile, r.Value.Label, IsAvailable: true)));
        }
        return (entries, errors);
    }

    /// <summary>Runs <paramref name="action"/> with the selected identity, reopening it once if the token session was lost.</summary>
    public T Use<T>(Func<ISigningIdentity, T> action)
    {
        _signing.Wait();
        try
        {
            var identity = GetOrOpen();
            try
            {
                return action(identity);
            }
            catch (IdentityLostException)
            {
                Invalidate(identity);
                return action(GetOrOpen());
            }
            catch (SignerException)
            {
                // e.g. the Windows-store token was unplugged: open fresh next time.
                Invalidate(identity);
                throw;
            }
        }
        finally
        {
            _signing.Release();
        }
    }

    /// <summary>Forget the opened identity (logs out of the token); the PIN will be asked again on next use.</summary>
    /// <remarks>Returns immediately; an identity still in use is disposed once its current signature finishes.</remarks>
    public void Lock()
    {
        ISigningIdentity? old;
        lock (_gate)
        {
            old = _cached;
            _cached = null;
            _cachedId = null;
        }
        if (old is IDisposable disposable)
        {
            _ = Task.Run(() =>
            {
                _signing.Wait();
                try { disposable.Dispose(); }
                finally { _signing.Release(); }
            });
        }
    }

    // Called with _signing held, so only one open can be in flight.
    private ISigningIdentity GetOrOpen()
    {
        for (var attempt = 0; ; attempt++)
        {
            string? id;
            lock (_gate)
            {
                if (_cached is not null && _cachedId == _selectedId) return _cached;
                id = _selectedId;
            }

            var opened = Open(id); // may prompt for a PIN: no lock held

            lock (_gate)
            {
                if (id == _selectedId || attempt > 0)
                {
                    (_cached as IDisposable)?.Dispose();
                    _cached = opened;
                    _cachedId = id;
                    return opened;
                }
            }
            // The user picked another certificate while we were opening this one: open the new choice instead.
            (opened as IDisposable)?.Dispose();
        }
    }

    private void Invalidate(ISigningIdentity identity)
    {
        lock (_gate)
        {
            if (!ReferenceEquals(_cached, identity)) return;
            _cached = null;
            _cachedId = null;
        }
        (identity as IDisposable)?.Dispose();
    }

    private ISigningIdentity Open(string? id)
    {
        if (id is null) throw new SignerException("No signing certificate is selected. Open DigSig and choose one.");
        var parts = id.Split(':', 2);
        switch (parts[0])
        {
            case "win" when OperatingSystem.IsWindows():
                return WindowsStoreSource.Open(parts[1]);
            case "p11":
                var library = Pkcs11Library ?? throw new SignerException("No PKCS#11 library is configured.");
                var serialAndThumbprint = parts[1].Split(':', 2);
                return GetModule(library).Open(serialAndThumbprint[0], serialAndThumbprint[1], secretPrompt);
            case "mem":
                lock (_gate)
                {
                    if (_registered.TryGetValue(id, out var registered)) return new NonOwningIdentity(registered.Identity);
                }
                throw new SignerException("The selected .pfx is no longer loaded; add it again.");
            default:
                throw new SignerException($"Unknown certificate source in \"{id}\".");
        }
    }

    private Pkcs11Module GetModule(string path)
    {
        lock (_modules)
        {
            if (!_modules.TryGetValue(path, out var module)) _modules[path] = module = new Pkcs11Module(path);
            return module;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            (_cached as IDisposable)?.Dispose();
            _cached = null;
        }
        foreach (var m in _modules.Values) m.Dispose();
        foreach (var (identity, _) in _registered.Values) (identity as IDisposable)?.Dispose();
    }

    // Registered identities outlive selection changes, so the cache must not dispose them.
    private sealed class NonOwningIdentity(ISigningIdentity inner) : ISigningIdentity
    {
        public X509Certificate2 Certificate => inner.Certificate;
        public IReadOnlyList<X509Certificate2> ExtraCertificates => inner.ExtraCertificates;
        public byte[] SignSha1(byte[] data) => inner.SignSha1(data);
    }
}
