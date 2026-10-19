using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Threading;

namespace DigSig.Desktop;

public partial class App : Application
{
    private MainViewModel? _vm;
    private MainWindow? _window;
    private TrayIcon? _tray;

    public static WindowIcon AppIcon { get; private set; } = null!;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is not IClassicDesktopStyleApplicationLifetime desktop)
        {
            base.OnFrameworkInitializationCompleted();
            return;
        }

        AppIcon = CreateIcon();
        var settings = AppSettings.Load();
        _vm = new MainViewModel(settings, PromptForSecret);
        _window = new MainWindow(_vm) { Icon = AppIcon };
        _window.ExitRequested += () => Quit(desktop);

        _tray = new TrayIcon { Icon = AppIcon, ToolTipText = "DigSig", Menu = new NativeMenu() };
        _tray.Clicked += (_, _) => ShowWindow();
        TrayIcon.SetIcons(this, [_tray]);
        _vm.CertificatesChanged += RebuildTrayMenu;
        RebuildTrayMenu();

        if (!settings.StartMinimized) _window.Show();
        _ = _vm.StartAsync();
        base.OnFrameworkInitializationCompleted();
    }

    private void ShowWindow()
    {
        if (_window is null) return;
        _window.Show();
        _window.WindowState = WindowState.Normal;
        _window.Activate();
    }

    private void RebuildTrayMenu()
    {
        if (_tray?.Menu is not { } menu || _vm is null) return;
        menu.Items.Clear();
        menu.Items.Add(new NativeMenuItem("Open DigSig") { Command = new RelayCommand(ShowWindow) });
        menu.Items.Add(new NativeMenuItemSeparator());
        foreach (var cert in _vm.Certificates.Where(c => c.IsUsable || c.IsActive))
        {
            var id = cert.Entry.Id;
            menu.Items.Add(new NativeMenuItem(cert.Title)
            {
                ToggleType = NativeMenuItemToggleType.Radio,
                IsChecked = cert.IsActive,
                Command = new RelayCommand(() => _vm.Activate(id)),
            });
        }
        menu.Items.Add(new NativeMenuItemSeparator());
        menu.Items.Add(new NativeMenuItem("Quit") { Command = new RelayCommand(() => Quit((IClassicDesktopStyleApplicationLifetime)ApplicationLifetime!)) });
        _tray.ToolTipText = "DigSig — " + _vm.ActiveSummary;
    }

    private async void Quit(IClassicDesktopStyleApplicationLifetime desktop)
    {
        if (_tray is not null) _tray.IsVisible = false;
        if (_vm is not null) await _vm.DisposeAsync();
        desktop.Shutdown();
    }

    /// <summary>Called from request threads when a token PIN or .pfx password is needed; blocks until the user answers.</summary>
    private static string? PromptForSecret(string prompt)
    {
        if (Dispatcher.UIThread.CheckAccess())
            throw new InvalidOperationException("Secrets must be requested off the UI thread.");
        var answer = new TaskCompletionSource<string?>();
        Dispatcher.UIThread.Post(async () =>
        {
            try { answer.SetResult(await SecretDialog.AskAsync(prompt)); }
            catch (Exception ex) { answer.SetException(ex); }
        });
        return answer.Task.GetAwaiter().GetResult();
    }

    // A simple generated icon (blue tile with a check mark), so the app ships without image assets.
    private static WindowIcon CreateIcon()
    {
        var bitmap = new RenderTargetBitmap(new PixelSize(64, 64), new Vector(96, 96));
        using (var ctx = bitmap.CreateDrawingContext())
        {
            ctx.DrawRectangle(new SolidColorBrush(Color.Parse("#1F6FEB")), null, new RoundedRect(new Rect(2, 2, 60, 60), 14));
            var pen = new Pen(Brushes.White, 7, lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round);
            ctx.DrawGeometry(null, pen, StreamGeometry.Parse("M 18,33 L 28,43 L 47,22"));
        }
        using var ms = new MemoryStream();
        bitmap.Save(ms);
        ms.Position = 0;
        return new WindowIcon(ms);
    }
}

internal sealed class RelayCommand(Action execute) : System.Windows.Input.ICommand
{
    public event EventHandler? CanExecuteChanged { add { } remove { } }
    public bool CanExecute(object? parameter) => true;
    public void Execute(object? parameter) => execute();
}
