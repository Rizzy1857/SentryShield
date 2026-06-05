using System.Windows.Controls;
using System.Windows;

namespace SentryShield.UI.Views
{
    public partial class FindingsView : Page
    {
        public FindingsView()
        {
            InitializeComponent();
            
            // Fix: Frame boundaries in WPF break DataContext inheritance.
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
