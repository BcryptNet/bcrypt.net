namespace BCrypt.Net
{
    public sealed class HashInformation
    {
        public HashInformation(string settings, string version, string workFactor, string rawHash)
        {
            Settings = settings;
            Version = version;
            WorkFactor = workFactor;
            RawHash = rawHash;
        }

        public string Settings { get; private set; }
        public string Version { get; private set; }
        public string WorkFactor { get; private set; }
        public string RawHash { get; private set; }
    }
}