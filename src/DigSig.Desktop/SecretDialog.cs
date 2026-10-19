using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;

namespace DigSig.Desktop;

/// <summary>Small always-on-top window asking for a token PIN or file password. The value is never stored on disk.</summary>
public sealed class SecretDialog : Window
{
    private readonly TaskCompletionSource<string?> _result = new();
    private readonly TextBox _input;

    private SecretDialog(string prompt)
    {
        Title = "DigSig";
        Icon = App.AppIcon;
        Width = 380;
        SizeToContent = SizeToContent.Height;
        CanResize = false;
        Topmost = true;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;

        _input = new TextBox { PasswordChar = '•', Watermark = "PIN" };
        var ok = new Button { Content = "OK", IsDefault = true, MinWidth = 80, HorizontalContentAlignment = HorizontalAlignment.Center };
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 80, HorizontalContentAlignment = HorizontalAlignment.Center };
        ok.Click += (_, _) => Finish(_input.Text ?? "");
        cancel.Click += (_, _) => Finish(null);
        _input.KeyDown += (_, e) => { if (e.Key == Key.Enter) Finish(_input.Text ?? ""); };

        Content = new StackPanel
        {
            Margin = new Thickness(20),
            Spacing = 12,
            Children =
            {
                new TextBlock { Text = prompt, TextWrapping = Avalonia.Media.TextWrapping.Wrap },
                _input,
                new TextBlock { Text = "Kept in memory only while the app runs.", Classes = { "muted" } },
                new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right, Children = { ok, cancel } },
            },
        };
        Opened += (_, _) => _input.Focus();
        Closed += (_, _) => _result.TrySetResult(null);
    }

    private void Finish(string? value)
    {
        _result.TrySetResult(value);
        Close();
    }

    public static Task<string?> AskAsync(string prompt)
    {
        var dialog = new SecretDialog(prompt);
        dialog.Show();
        dialog.Activate();
        return dialog._result.Task;
    }
}
