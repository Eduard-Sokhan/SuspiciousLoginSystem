using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using MySql.Data.MySqlClient;
using SuspiciousLoginSystem.Database;
using SuspiciousLoginSystem.Services;

namespace SuspiciousLoginSystem
{
    public partial class LoginWindow : Window
    {
        private int localFailedAttempts = 0;
        private string lastUsername = "";
        

        public LoginWindow()
        {
            InitializeComponent();

            var config = AppConfig.Load();
            this.Title = config.AppName + " v" + config.Version;

            txtUsername.TextChanged += TxtUsername_TextChanged;

            if (config.TestMode)
            {
                ShowMessage("TEST MODE ENABLED", "warning");
            }
        }

        private void TxtUsername_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            if (txtUsername.Text != lastUsername)
            {
                localFailedAttempts = 0;
                btnLogin.IsEnabled = true;
                HideMessage();
            }
        }

        private async void Login_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                HideMessage();

                var config = AppConfig.Load();
                DatabaseService db = new DatabaseService();

                if (string.IsNullOrWhiteSpace(txtUsername.Text) ||
                    string.IsNullOrWhiteSpace(txtPassword.Password))
                {
                    ShowMessage("Fill all fields!", "error");
                    return;
                }

                string password = "", regIP = "", regCountry = "", regDevice = "";
                int failedAttempts = 0;

                using (MySqlConnection conn = db.GetConnection())
                {
                    conn.Open();
                    using (var cmd = new MySqlCommand("SELECT * FROM users WHERE username=@u", conn))
                    {
                        cmd.Parameters.AddWithValue("@u", txtUsername.Text);

                        using (var reader = cmd.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                password = reader["password"].ToString();
                                regIP = reader["ip"].ToString();
                                regCountry = reader["country"].ToString();
                                regDevice = reader["device"].ToString();
                                failedAttempts = Convert.ToInt32(reader["failed_attempts"]);
                            }
                            else
                            {
                                ShowMessage("User not found!", "error");
                                return;
                            }
                        }
                    }
                }

                string loginIP, loginCountry, loginDevice;

                if (config.TestMode)
                {
                    loginIP = config.TestIP;
                    loginCountry = config.TestCountry;
                    loginDevice = config.TestDevice;
                }
                else
                {
                    NetworkService network = new NetworkService();
                    loginIP = network.GetIP();
                    loginCountry = network.GetCountry(loginIP);
                    loginDevice = network.GetDevice();
                }

                if (password != txtPassword.Password)
                {
                    localFailedAttempts++;
                    lastUsername = txtUsername.Text;

                    using (MySqlConnection conn = db.GetConnection())
                    {
                        conn.Open();
                        using (var cmd = new MySqlCommand(
                            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username=@u", conn))
                        {
                            cmd.Parameters.AddWithValue("@u", txtUsername.Text);
                            cmd.ExecuteNonQuery();
                        }
                    }

                    var reportFail = RiskAnalyzer.GenerateRiskReport(
                        regIP, loginIP,
                        regCountry, loginCountry,
                        regDevice, loginDevice,
                        failedAttempts + 1
                    );
                    UpdateRiskUI(reportFail.Risk, config);

                    if (localFailedAttempts >= 5)
                    {
                        btnLogin.IsEnabled = false;
                        ShowMessage("❌ Too many attempts! Change username.", "error");
                    }
                    else
                    {
                        ShowMessage($"Incorrect password! ({localFailedAttempts}/5)", "error");
                    }

                    return;
                }

                localFailedAttempts = 0;

                using (MySqlConnection conn = db.GetConnection())
                {
                    conn.Open();
                    using (var cmd = new MySqlCommand(
                        "UPDATE users SET failed_attempts = 0 WHERE username=@u", conn))
                    {
                        cmd.Parameters.AddWithValue("@u", txtUsername.Text);
                        cmd.ExecuteNonQuery();
                    }
                }

                var report = RiskAnalyzer.GenerateRiskReport(
                    regIP, loginIP,
                    regCountry, loginCountry,
                    regDevice, loginDevice,
                    0
                );
                UpdateRiskUI(report.Risk, config);

                ShowMessage("Login successful!", "success");
            }
            catch (Exception ex)
            {
                ShowMessage("Error: " + ex.Message, "error");
            }
        }

        private void UpdateRiskUI(int value, dynamic config)
        {
            riskBar.Value = value;

            if (value < 30)
                riskBar.Foreground = Brushes.Green;
            else if (value >= 30 && value <= 70)
                riskBar.Foreground = Brushes.Orange;
            else
                riskBar.Foreground = Brushes.Red;

            lblResult.Text = $"Trust: {value}";
        }

        private async void ShowMessage(string message, string type)
        {
            messageBox.Visibility = Visibility.Visible;
            lblMessage.Text = message;

            lblIcon.Text = type == "error" ? "❌" :
                           type == "success" ? "✅" :
                           "⚠";

            switch (type)
            {
                case "error":
                    messageBox.Background = (Brush)new BrushConverter().ConvertFrom("#FF4C4C");
                    break;

                case "success":
                    messageBox.Background = (Brush)new BrushConverter().ConvertFrom("#4CAF50");
                    break;

                case "warning":
                    messageBox.Background = (Brush)new BrushConverter().ConvertFrom("#FFA500");
                    break;
            }

            await Task.Delay(3000);
            HideMessage();
        }

        private void HideMessage()
        {
            messageBox.Visibility = Visibility.Collapsed;
        }

        private void CloseMessage_Click(object sender, RoutedEventArgs e)
        {
            HideMessage();
        }

        private void GoToRegister_Click(object sender, RoutedEventArgs e)
        {
            new RegisterWindow().Show();
            this.Close();
        }

        private void OpenSettings_Click(object sender, RoutedEventArgs e)
        {
            var wnd = new SettingsWindow();
            wnd.Owner = this;
            wnd.ShowDialog();
        }

        // ExportReport handler removed when export button was deleted from UI.
    }
}