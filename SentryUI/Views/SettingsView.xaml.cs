using System.Windows.Controls;
using System.Windows;

namespace SentryShield.UI.Views
{
    public partial class SettingsView : Page
    {
        public SettingsView()
        {
            InitializeComponent();
            
            // Fix: Frame boundaries in WPF break DataContext inheritance.
            // When the SettingsView loads, grab the DataContext from the parent MainWindow
            // so the Sync button and Terminal UI can bind to the shared DashboardViewModel.
            this.Loaded += (s, e) => 
            {
                var window = Window.GetWindow(this);
                if (window != null)
                {
                    this.DataContext = window.DataContext;
                }
            };
        }
    }
}
