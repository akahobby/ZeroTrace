using System;
using System.Drawing;
using System.IO;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace ZeroTrace.App.Helpers;

public static class IconHelper
{
    public static ImageSource? TryLoadIcon(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            string candidate = path;

            // Some DisplayIcon values may contain arguments or indexes (e.g. "app.exe,0")
            var commaIndex = candidate.IndexOf(',');
            if (commaIndex > 0)
            {
                candidate = candidate[..commaIndex];
            }

            candidate = candidate.Trim('"');

            if (!File.Exists(candidate))
            {
                return null;
            }

            using Icon? icon = Icon.ExtractAssociatedIcon(candidate);
            if (icon is null)
            {
                return null;
            }

            var handle = icon.Handle;
            var source = Imaging.CreateBitmapSourceFromHIcon(
                handle,
                Int32Rect.Empty,
                BitmapSizeOptions.FromEmptyOptions());
            source.Freeze();
            return source;
        }
        catch
        {
            return null;
        }
    }
}

