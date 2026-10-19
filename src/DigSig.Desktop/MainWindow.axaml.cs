using Avalonia.Controls;
using Avalonia.Data.Converters;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Platform.Storage;

namespace DigSig.Desktop;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;

    public event Action? ExitRequested;

    // Required by the XAML loader/previewer.
    public MainWindow() : this(null!) { }

    public MainWindow(MainViewModel vm)
    {
        _vm = vm;
        DataContext = vm;
        InitializeComponent();
        Closing += (_, e) =>
        {
            if (e.CloseReason is WindowCloseReason.ApplicationShutdown or WindowCloseReason.OSShutdown) return;
            e.Cancel = true;
            if (_vm.CloseToTray) Hide();
            else ExitRequested?.Invoke();
        };
    }

    private void OnCertificateSelected(object? sender, SelectionChangedEventArgs e)
    {
        if (CertificateList.SelectedItem is CertificateItem item)
        {
            _vm.Activate(item);
            CertificateList.SelectedItem = null; // the radio button shows the active one; keep the list clickable
        }
    }

    private async void OnRefresh(object? sender, RoutedEventArgs e) => await _vm.RefreshAsync();

    private async void OnTestSignature(object? sender, RoutedEventArgs e) => await _vm.TestSignatureAsync();

    private void OnLock(object? sender, RoutedEventArgs e) => _vm.Lock();

    private async void OnApplyServer(object? sender, RoutedEventArgs e) => await _vm.ApplyServerSettingsAsync();

    private void OnTrustHttps(object? sender, RoutedEventArgs e) => _vm.TrustHttpsCertificate();

    private async void OnImportHttps(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Select the original DigSig application (digsig-signer-*.jar)",
            FileTypeFilter = [new FilePickerFileType("Java archive") { Patterns = ["*.jar"] }],
        });
        if (files.Count > 0 && files[0].TryGetLocalPath() is { } path) await _vm.ImportHttpsCertificateAsync(path);
    }

    private async void OnOpenInBrowser(object? sender, RoutedEventArgs e) =>
        await Launcher.LaunchUriAsync(new Uri($"https://localhost:{_vm.Port}/"));

    private async void OnBrowsePkcs11(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Select the token's PKCS#11 library",
            FileTypeFilter = [new FilePickerFileType("PKCS#11 library") { Patterns = ["*.dll", "*.so", "*.so.*", "*.dylib"] }],
        });
        if (files.Count > 0 && files[0].TryGetLocalPath() is { } path) _vm.Pkcs11Library = path;
    }

    private async void OnAddPfx(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Select a .pfx / .p12 certificate file",
            FileTypeFilter = [new FilePickerFileType("Certificate with private key") { Patterns = ["*.pfx", "*.p12"] }],
        });
        if (files.Count == 0 || files[0].TryGetLocalPath() is not { } path) return;
        var password = await SecretDialog.AskAsync($"Enter the password for {Path.GetFileName(path)}");
        if (password is not null) await _vm.AddPfxAsync(path, password);
    }
}

public static class Converters
{
    private static readonly IBrush Ok = new SolidColorBrush(Color.Parse("#2EA043"));
    private static readonly IBrush Bad = new SolidColorBrush(Color.Parse("#8B949E"));
    private static readonly IBrush Failed = new SolidColorBrush(Color.Parse("#DA3633"));

    public static readonly IValueConverter StatusBrush = new FuncValueConverter<bool, IBrush>(ok => ok ? Ok : Bad);
    public static readonly IValueConverter FailureBrush = new FuncValueConverter<bool, IBrush>(ok => ok ? Ok : Failed);
    public static readonly IValueConverter UsableOpacity = new FuncValueConverter<bool, double>(usable => usable ? 1.0 : 0.55);
}
