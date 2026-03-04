using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using ZeroTrace.Core.Models;

namespace ZeroTrace.App.Windows;

public partial class LeftoverWindow : Window
{
    public IList<LeftoverItem> Leftovers { get; }

    public IReadOnlyList<LeftoverItem> SelectedForDeletion =>
        Leftovers.Where(l => l.IsSelected).ToList();

    public LeftoverWindow(IList<LeftoverItem> leftovers)
    {
        Leftovers = leftovers ?? throw new ArgumentNullException(nameof(leftovers));
        InitializeComponent();
        DataContext = this;
    }

    private void OnRemoveSelectedClick(object sender, RoutedEventArgs e)
    {
        if (!SelectedForDeletion.Any())
        {
            MessageBox.Show(
                "No items have been selected for removal.",
                "ZeroTrace",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        DialogResult = true;
        Close();
    }

    private void OnSelectAllClick(object sender, RoutedEventArgs e)
    {
        foreach (var leftover in Leftovers)
        {
            leftover.IsSelected = true;
        }

        LeftoversGrid.Items.Refresh();
    }
}

