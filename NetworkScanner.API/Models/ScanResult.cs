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
        
        // Scan status information
        public string? Status { get; set; }
        public string? ErrorMessage { get; set; }
    }

    /// <summary>
    /// Represents a request to scan a machine
    /// </summary>
    public class ScanRequest
    {
        public required string IpAddress { get; set; }
    }
}