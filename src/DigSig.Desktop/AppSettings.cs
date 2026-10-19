using System.Text.Json;
using DigSig.Core.Keys;
using DigSig.Core.Server;

namespace DigSig.Desktop;

/// <summary>Per-user settings, stored as JSON in the OS application-data folder. No PINs or passwords are stored.</summary>
public sealed class AppSettings
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static string FilePath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DigSig", "settings.json");

    public string? SelectedCertificateId { get; set; }
    public bool UseWindowsStore { get; set; } = OperatingSystem.IsWindows();
    public bool UsePkcs11 { get; set; } = !OperatingSystem.IsWindows();
    public string? Pkcs11Library { get; set; } = Pkcs11Module.FindDefaultLibrary();
    public int Port { get; set; } = SignerServerOptions.DefaultPort;
    public List<string> AllowedOrigins { get; set; } = [];
    public bool StartMinimized { get; set; }
    public bool CloseToTray { get; set; } = true;

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath)) return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath), JsonOptions) ?? new();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // Corrupt or unreadable settings: start from defaults rather than refusing to run.
        }
        return new AppSettings();
    }

    public void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(this, JsonOptions));
    }
}
