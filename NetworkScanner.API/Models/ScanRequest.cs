// Models/ScanRequest.cs
namespace NetworkScanner.API.Models
{
    /// <summary>
    /// Represents a request to scan a single machine
    /// </summary>
    public class ScanRequest
    {
        public required string IpAddress { get; set; }
    }

    /// <summary>
    /// Represents a request to scan multiple machines
    /// </summary>
    public class BatchScanRequest
    {
        /// <summary>
        /// List of specific IP addresses to scan
        /// </summary>
        public List<string>? IpAddresses { get; set; }
        
        /// <summary>
        /// List of IP ranges to scan in the format "192.168.1.1-192.168.1.254" or "192.168.1.0/24"
        /// </summary>
        public List<string>? IpRanges { get; set; }
    }

    /// <summary>
    /// Represents the result of a batch scan operation
    /// </summary>
    public class BatchScanResponse
    {
        /// <summary>
        /// The total number of IP addresses being scanned
        /// </summary>
        public int TotalIps { get; set; }
        
        /// <summary>
        /// The number of IP addresses that have been scanned so far
        /// </summary>
        public int ScannedIps { get; set; }
        
        /// <summary>
        /// The number of successful scans
        /// </summary>
        public int SuccessfulScans { get; set; }
        
        /// <summary>
        /// The number of failed scans
        /// </summary>
        public int FailedScans { get; set; }
        
        /// <summary>
        /// The results of the scans that have been completed
        /// </summary>
        public List<ScanResult> Results { get; set; } = new List<ScanResult>();
    }
}