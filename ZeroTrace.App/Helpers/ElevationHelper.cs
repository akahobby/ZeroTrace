using System;
using System.Diagnostics;
using System.Windows;
using ZeroTrace.Core.Services;

namespace ZeroTrace.App.Helpers;

public static class ElevationHelper
{
    public static void RestartAsAdministrator()
    {
        try
        {
            if (UninstallCoordinator.IsRunningAsAdministrator())
            {
                MessageBox.Show(
                    "ZeroTrace is already running with administrative privileges.",
                    "ZeroTrace",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            var exePath = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(exePath))
            {
                MessageBox.Show(
                    "Unable to locate the current executable to restart as administrator.",
                    "ZeroTrace",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                return;
            }

            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                UseShellExecute = true,
                Verb = "runas"
            };

            Process.Start(psi);
            Application.Current.Shutdown();
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Failed to restart ZeroTrace as administrator: {ex.Message}",
                "ZeroTrace",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }
}

