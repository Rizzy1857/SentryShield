using System.Windows;
using System.Windows.Controls;
using System.Collections.Specialized;
using SentryShield.UI.ViewModels;

namespace SentryShield.UI.Views
{
    public partial class ScanView : Page
    {
        public ScanView()
        {
            InitializeComponent();
            
            // Bridge the DataContext across the Frame boundary
            this.Loaded += (s, e) =>
            {
                if (Window.GetWindow(this) is MainWindow mainWindow)
                {
                    this.DataContext = mainWindow.DataContext;
                    
                    // Auto-scroll the terminal when logs are added
                    if (this.DataContext is DashboardViewModel vm)
                    {
                        vm.ScanLogs.CollectionChanged += ScanLogs_CollectionChanged;
                    }
                }
            };
            
            this.Unloaded += (s, e) => 
            {
                if (this.DataContext is DashboardViewModel vm)
                {
                    vm.ScanLogs.CollectionChanged -= ScanLogs_CollectionChanged;
                }
            };
        }

        private void ScanLogs_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            if (e.Action == NotifyCollectionChangedAction.Add)
            {
                TerminalScrollViewer.ScrollToBottom();
            }
        }
    }
}
