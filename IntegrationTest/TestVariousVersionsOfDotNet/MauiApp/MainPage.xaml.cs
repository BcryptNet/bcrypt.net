using System.Diagnostics;

namespace MauiApp
{
    public partial class MainPage : ContentPage
    {
        int count = 0;

        public MainPage()
        {
            InitializeComponent();
        }

        private void OnCounterClicked(object sender, EventArgs e)
        {

            var sw = Stopwatch.StartNew();
            BCrypt.Net.BCrypt.Verify("111111", "$2a$12$luf9xtzcPijRzyMnb1PxsuqFUsBba0ve.R.5k00XOsGf2awcHwj8a");
            sw.Stop();

            count++;

            if (count == 1)
                CounterBtn.Text = $"Clicked {count} time, took {sw.ElapsedMilliseconds}ms";
            else
                CounterBtn.Text = $"Clicked {count} times, took {sw.ElapsedMilliseconds}ms";

            SemanticScreenReader.Announce(CounterBtn.Text);
        }
    }

}
