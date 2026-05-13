using System.IO;
using Newtonsoft.Json;

namespace SuspiciousLoginSystem.Services
{
    public class AppConfig
    {
        public string AppName { get; set; }
        public string Version { get; set; }
        public int DefaultRiskThreshold { get; set; }
        public string LogFilePath { get; set; }
        public bool TestMode { get; set; }
        public string TestIP { get; set; }
        public string TestCountry { get; set; }
        public string TestDevice { get; set; }
        public int IpWeight { get; set; } = 30;
        public int CountryWeight { get; set; } = 30;
        public int DeviceWeight { get; set; } = 20;
        public int DeviceSimilarityWeight { get; set; } = 10;
        public int DeviceSimilarityTokenThreshold { get; set; } = 1;
        public int FailedAttemptWeight { get; set; } = 10;
        public int FailedAttemptCap { get; set; } = 5;
        public int SubnetMatchWeight { get; set; } = 10;
        public int SubnetPrefixLength { get; set; } = 24;

        public static AppConfig Load()
        {
            string json = File.ReadAllText("config.json");
            return JsonConvert.DeserializeObject<AppConfig>(json);
        }

        public void Save()
        {
            string json = JsonConvert.SerializeObject(this, Formatting.Indented);
            File.WriteAllText("config.json", json);
        }
    }
}