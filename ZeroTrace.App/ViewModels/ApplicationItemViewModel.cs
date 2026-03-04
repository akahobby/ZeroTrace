using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Media;
using ZeroTrace.Core.Models;

namespace ZeroTrace.App.ViewModels;

public sealed class ApplicationItemViewModel : INotifyPropertyChanged
{
    public InstalledApplication Model { get; }

    private ImageSource? _icon;
    private string? _displaySize;

    public event PropertyChangedEventHandler? PropertyChanged;

    public ApplicationItemViewModel(InstalledApplication model)
    {
        Model = model ?? throw new ArgumentNullException(nameof(model));
    }

    public string Name => Model.DisplayName;
    public string? Publisher => Model.Publisher;
    public string? Version => Model.DisplayVersion;
    public string? InstallLocation => Model.InstallLocation;
    public long? SizeBytes => Model.EstimatedSizeBytes;
    public bool IsSteam => Model.IsSteam;
    public DateTime? InstallDate => Model.InstallDate;

    public string DisplaySize
    {
        get
        {
            if (_displaySize is not null)
            {
                return _displaySize;
            }

            if (SizeBytes is long sizeFromRegistry && sizeFromRegistry > 0)
            {
                _displaySize = FormatSize(sizeFromRegistry);
                return _displaySize;
            }

            if (!string.IsNullOrWhiteSpace(InstallLocation) && Directory.Exists(InstallLocation))
            {
                try
                {
                    long total = 0;
                    foreach (var file in Directory.EnumerateFiles(InstallLocation, "*", SearchOption.AllDirectories))
                    {
                        try
                        {
                            var info = new FileInfo(file);
                            if (info.Exists)
                            {
                                total += info.Length;
                            }
                        }
                        catch
                        {
                            // Ignore individual file errors
                        }
                    }

                    if (total > 0)
                    {
                        _displaySize = FormatSize(total);
                        return _displaySize;
                    }
                }
                catch
                {
                    // Ignore directory errors
                }
            }

            _displaySize = "Unknown";
            return _displaySize;
        }
    }

    public string DisplayInstallDate =>
        InstallDate.HasValue && IsPlausibleInstallDate(InstallDate.Value)
            ? InstallDate.Value.ToString("yyyy-MM-dd")
            : "Unknown";

    private static bool IsPlausibleInstallDate(DateTime date)
    {
        var min = new DateTime(1990, 1, 1);
        var max = DateTime.Today.AddYears(1);
        return date >= min && date <= max;
    }

    public ImageSource? Icon
    {
        get => _icon;
        set
        {
            if (!Equals(_icon, value))
            {
                _icon = value;
                OnPropertyChanged();
            }
        }
    }

    private static string FormatSize(long bytes)
    {
        const long OneKB = 1024;
        const long OneMB = OneKB * 1024;
        const long OneGB = OneMB * 1024;

        if (bytes >= OneGB)
        {
            return $"{bytes / (double)OneGB:0.##} GB";
        }
        if (bytes >= OneMB)
        {
            return $"{bytes / (double)OneMB:0.##} MB";
        }
        if (bytes >= OneKB)
        {
            return $"{bytes / (double)OneKB:0.##} KB";
        }

        return $"{bytes} B";
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

