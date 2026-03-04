using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using ZeroTrace.App.Helpers;
using ZeroTrace.App.ViewModels;
using ZeroTrace.App.Windows;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Services;

namespace ZeroTrace.App;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private readonly LogService _logService;
    private readonly ApplicationService _applicationService;
    private readonly LeftoverScanner _leftoverScanner;
    private readonly UninstallCoordinator _uninstallCoordinator;
    private readonly LeftoverDeletionService _deletionService;

    private readonly ObservableCollection<ApplicationItemViewModel> _applications = new();
    private ICollectionView? _applicationsView;

    private ApplicationItemViewModel? _selectedApplication;
    private string _searchText = string.Empty;
    private bool _isOperationInProgress;
    private CancellationTokenSource? _operationCts;

    public event PropertyChangedEventHandler? PropertyChanged;

    public MainWindow()
    {
        InitializeComponent();

        _logService = new LogService();

        var registryProvider = new RegistryApplicationProvider(_logService);
        var steamProvider = new SteamApplicationProvider(_logService);

        _applicationService = new ApplicationService(registryProvider, steamProvider, _logService);
        _leftoverScanner = new LeftoverScanner(_logService);
        _uninstallCoordinator = new UninstallCoordinator(_logService);
        _deletionService = new LeftoverDeletionService(_logService);

        DataContext = this;

        Loaded += async (_, _) => await LoadApplicationsAsync();
        Closing += (_, _) => _logService.Dispose();

        _applicationsView = CollectionViewSource.GetDefaultView(_applications);
        _applicationsView.Filter = FilterApplications;
    }

    public ICollectionView ApplicationsView => _applicationsView!;

    public ApplicationItemViewModel? SelectedApplication
    {
        get => _selectedApplication;
        set
        {
            if (!Equals(_selectedApplication, value))
            {
                _selectedApplication = value;
                OnPropertyChanged(nameof(SelectedApplication));
                OnPropertyChanged(nameof(CanUninstall));
            }
        }
    }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (_searchText != value)
            {
                _searchText = value;
                OnPropertyChanged(nameof(SearchText));
                _applicationsView?.Refresh();
            }
        }
    }

    public bool IsOperationInProgress
    {
        get => _isOperationInProgress;
        private set
        {
            if (_isOperationInProgress != value)
            {
                _isOperationInProgress = value;
                OnPropertyChanged(nameof(IsOperationInProgress));
                OnPropertyChanged(nameof(CanUninstall));
            }
        }
    }

    public bool CanUninstall => SelectedApplication is not null && !IsOperationInProgress;

    private async Task LoadApplicationsAsync()
    {
        try
        {
            _logService.Info("Loading installed applications...");
            _applications.Clear();

            var apps = await _applicationService.GetInstalledApplicationsAsync();

            foreach (var app in apps)
            {
                var vm = new ApplicationItemViewModel(app)
                {
                    Icon = ResolveIconForApp(app)
                };
                _applications.Add(vm);
            }

            _applicationsView?.Refresh();
            _logService.Info("Installed applications loaded.");
        }
        catch (System.Exception ex)
        {
            _logService.Error($"Failed to load applications: {ex.Message}");
            MessageBox.Show(
                "Failed to load installed applications. See log for details.",
                "ZeroTrace",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private static ImageSource? ResolveIconForApp(InstalledApplication app)
    {
        // Prefer the registry DisplayIcon when available.
        var iconPath = app.DisplayIconPath;
        var icon = IconHelper.TryLoadIcon(iconPath);
        if (icon is not null)
        {
            return icon;
        }

        // Fallback: use the icon from the main executable under InstallLocation.
        if (!string.IsNullOrWhiteSpace(app.InstallLocation))
        {
            try
            {
                var exe = System.IO.Directory
                    .EnumerateFiles(app.InstallLocation, "*.exe", System.IO.SearchOption.AllDirectories)
                    .FirstOrDefault();

                if (!string.IsNullOrWhiteSpace(exe))
                {
                    return IconHelper.TryLoadIcon(exe);
                }
            }
            catch
            {
                // ignored
            }
        }

        // If everything fails, no icon; Windows will show its default.
        return null;
    }

    private bool FilterApplications(object obj)
    {
        if (obj is not ApplicationItemViewModel vm)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(SearchText))
        {
            return true;
        }

        var term = SearchText.Trim();
        return (!string.IsNullOrEmpty(vm.Name) &&
                vm.Name.Contains(term, System.StringComparison.OrdinalIgnoreCase)) ||
               (!string.IsNullOrEmpty(vm.Publisher) &&
                vm.Publisher.Contains(term, System.StringComparison.OrdinalIgnoreCase));
    }

    private async void OnUninstallClick(object sender, RoutedEventArgs e)
    {
        if (SelectedApplication is null)
        {
            return;
        }

        var appVm = SelectedApplication;

        var confirm = MessageBox.Show(
            $"ZeroTrace will launch the official uninstaller for:\n\n{appVm.Name}\n\nContinue?",
            "Confirm Uninstall",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        _operationCts = new CancellationTokenSource();
        IsOperationInProgress = true;

        try
        {
            var success = await _uninstallCoordinator.UninstallAsync(appVm.Model, _operationCts.Token);

            if (!success)
            {
                _logService.Warn($"Uninstall did not complete successfully for '{appVm.Name}'.");
            }

            if (!_operationCts.IsCancellationRequested)
            {
                await RunLeftoverFlowAsync(appVm.Model, _operationCts.Token);
            }

            await LoadApplicationsAsync();
        }
        finally
        {
            IsOperationInProgress = false;
            _operationCts?.Dispose();
            _operationCts = null;
        }
    }

    private async Task RunLeftoverFlowAsync(InstalledApplication app, CancellationToken token)
    {
        var leftovers = await _leftoverScanner.ScanAsync(app, token);

        if (leftovers.Count == 0)
        {
            _logService.Info("No leftovers detected.");
            return;
        }

        Dispatcher.Invoke(() =>
        {
            var window = new LeftoverWindow(leftovers.ToList())
            {
                Owner = this
            };

            var result = window.ShowDialog();
            if (result == true)
            {
                var selected = window.SelectedForDeletion;
                if (selected.Count > 0)
                {
                    _ = _deletionService.DeleteAsync(app, selected, token);
                }
            }
        });
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        _operationCts?.Cancel();
    }

    private void OnPropertyChanged(string propertyName)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}