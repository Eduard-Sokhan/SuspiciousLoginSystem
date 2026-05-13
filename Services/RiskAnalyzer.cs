using System;
using System.Net;
using SuspiciousLoginSystem.Models;

namespace SuspiciousLoginSystem.Services
{
    public static class RiskAnalyzer
    {
        public static int CalculateRiskWithFactors(
            string regIP, string loginIP,
            string regCountry, string loginCountry,
            string regDevice, string loginDevice,
            int failedAttempts)
        {
            var report = GenerateRiskReport(regIP, loginIP, regCountry, loginCountry, regDevice, loginDevice, failedAttempts);
            return report.Risk;
        }

        public static RiskReport GenerateRiskReport(
            string regIP, string loginIP,
            string regCountry, string loginCountry,
            string regDevice, string loginDevice,
            int failedAttempts)
        {
            AppConfig cfg;
            try
            {
                cfg = AppConfig.Load();
            }
            catch
            {
                cfg = new AppConfig();
            }

            static string Norm(string s) => (s ?? string.Empty).Trim().ToLowerInvariant();

            var report = new RiskReport
            {
                RegIP = regIP,
                LoginIP = loginIP,
                RegCountry = regCountry,
                LoginCountry = loginCountry,
                RegDevice = regDevice,
                LoginDevice = loginDevice,
                FailedAttempts = Math.Max(0, failedAttempts)
            };

            bool ipsEqual = false;
            if (!string.IsNullOrWhiteSpace(regIP) && !string.IsNullOrWhiteSpace(loginIP))
            {
                if (IPAddress.TryParse(regIP, out var ip1) && IPAddress.TryParse(loginIP, out var ip2))
                {
                    ipsEqual = ip1.Equals(ip2);
                }
                else
                {
                    ipsEqual = Norm(regIP) == Norm(loginIP);
                }
            }
            else
            {
                ipsEqual = Norm(regIP) == Norm(loginIP);
            }

            int risk = 0;
            if (!ipsEqual)
            {
                report.IpChanged = true;
                if (IPAddress.TryParse(regIP, out var tip1) && IPAddress.TryParse(loginIP, out var tip2)
                    && tip1.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                    && tip2.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                if (IPAddress.TryParse(regIP, out var tip1) && IPAddress.TryParse(loginIP, out var tip2)
                    && tip1.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                    && tip2.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    // Check prefix match
                    bool subnetMatch = false;
                    try
                    {
                        byte[] b1 = tip1.GetAddressBytes();
                        byte[] b2 = tip2.GetAddressBytes();
                        int prefix = Math.Max(0, Math.Min(32, cfg.SubnetPrefixLength));
                        int fullBytes = prefix / 8;
                        int remBits = prefix % 8;

                        subnetMatch = true;
                        for (int i = 0; i < fullBytes; i++)
                        {
                            if (b1[i] != b2[i]) { subnetMatch = false; break; }
                        }
                        if (subnetMatch && remBits > 0)
                        {
                            byte mask = (byte)(~(0xFF >> remBits));
                            if ((b1[fullBytes] & mask) != (b2[fullBytes] & mask)) subnetMatch = false;
                        }
                    }
                    catch
                    {
                        subnetMatch = false;
                    }

                    if (subnetMatch)
                    {
                        report.Contributions["IpSubnet"] = cfg.SubnetMatchWeight;
                        risk += cfg.SubnetMatchWeight;
                    }
                    else
                    {
                        report.Contributions["Ip"] = cfg.IpWeight;
                        risk += cfg.IpWeight;
                    }
                }
                else
                {
                    report.Contributions["Ip"] = cfg.IpWeight;
                    risk += cfg.IpWeight;
                }
            }

            if (Norm(regCountry) != Norm(loginCountry))
            {
                report.CountryChanged = true;
                report.Contributions["Country"] = cfg.CountryWeight;
                risk += cfg.CountryWeight;
            }

            if (Norm(regDevice) != Norm(loginDevice))
            {
                report.DeviceChanged = true;
                // Device similarity: split on non-alphanumeric and compare tokens
                try
                {
                    var toks1 = System.Text.RegularExpressions.Regex.Split(Norm(regDevice), "[^a-z0-9]+");
                    var toks2 = System.Text.RegularExpressions.Regex.Split(Norm(loginDevice), "[^a-z0-9]+");
                    var set1 = new System.Collections.Generic.HashSet<string>(toks1);
                    int common = 0;
                    foreach (var t in toks2)
                    {
                        if (string.IsNullOrEmpty(t)) continue;
                        if (set1.Contains(t)) common++;
                    }

                    if (common >= cfg.DeviceSimilarityTokenThreshold)
                    {
                        report.Contributions["DeviceSimilar"] = cfg.DeviceSimilarityWeight;
                        risk += cfg.DeviceSimilarityWeight;
                    }
                    else
                    {
                        report.Contributions["Device"] = cfg.DeviceWeight;
                        risk += cfg.DeviceWeight;
                    }
                }
                catch
                {
                    report.Contributions["Device"] = cfg.DeviceWeight;
                    risk += cfg.DeviceWeight;
                }
            }

            int cappedFailed = Math.Min(report.FailedAttempts, cfg.FailedAttemptCap);
            if (cappedFailed > 0)
            {
                report.Contributions["FailedAttempts"] = cappedFailed * cfg.FailedAttemptWeight;
                risk += report.Contributions["FailedAttempts"];
            }

            if (risk > 100) risk = 100;
            report.Risk = risk;
            return report;
        }
    }
}