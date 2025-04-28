// Models/ScanResult.cs
namespace NetworkScanner.API.Models
{
    /// <summary>
    /// Represents the result of a machine scan
    /// </summary>
    public class ScanResult
    {
        // Basic machine information
        public string? IpAddress { get; set; }
        public string? Hostname { get; set; }
        public string? RamSize { get; set; }
        
        // System information
        public string? WindowsVersion { get; set; }
        public string? WindowsRelease { get; set; }
        public string? OfficeVersion { get; set; }
        public string? MachineType { get; set; }
        public string? MachineSku { get; set; }
        public string? LastLoggedUser { get; set; }
        
        // Hardware information
        public string? CpuInfo { get; set; }
        public string? GpuInfo { get; set; }
        public string? DiskSize { get; set; }
        public string? DiskFreeSpace { get; set; }
        public string? BiosVersion { get; set; }
        
        // Network information
        public string? MacAddress { get; set; }
        public List<int>? OpenPorts { get; set; }
        
        // Scan status information
        public string? Status { get; set; }
        public string? ErrorMessage { get; set; }
        
        // Performance metrics
        public long ScanTimeMs { get; set; }
    }
}