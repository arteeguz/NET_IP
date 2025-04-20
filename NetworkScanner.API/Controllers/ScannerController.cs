// Controllers/ScannerController.cs
using Microsoft.AspNetCore.Mvc;
using NetworkScanner.API.Models;
using NetworkScanner.API.Services;

namespace NetworkScanner.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ScannerController : ControllerBase
    {
        private readonly NetworkScannerService _scannerService;
        private readonly IpRangeService _ipRangeService;
        private readonly ILogger<ScannerController> _logger;

        public ScannerController(
            NetworkScannerService scannerService, 
            IpRangeService ipRangeService,
            ILogger<ScannerController> logger)
        {
            _scannerService = scannerService;
            _ipRangeService = ipRangeService;
            _logger = logger;
        }

        /// <summary>
        /// Endpoint to scan a single machine by IP address
        /// </summary>
        [HttpPost("scan")]
        public IActionResult ScanMachine([FromBody] ScanRequest request)
        {
            if (string.IsNullOrEmpty(request.IpAddress))
            {
                return BadRequest("IP address is required");
            }

            _logger.LogInformation($"Scanning machine at IP: {request.IpAddress}");
            var result = _scannerService.ScanMachine(request.IpAddress);
            
            return Ok(result);
        }
        
        /// <summary>
        /// Endpoint to scan multiple machines by IP addresses and/or IP ranges
        /// </summary>
        [HttpPost("batch-scan")]
        public async Task<IActionResult> ScanMachines([FromBody] BatchScanRequest request)
        {
            // Collect all IP addresses to scan
            var ipAddresses = new List<string>();
            
            // Add specific IP addresses
            if (request.IpAddresses != null && request.IpAddresses.Any())
            {
                ipAddresses.AddRange(request.IpAddresses.Where(ip => !string.IsNullOrWhiteSpace(ip)));
            }
            
            // Parse and add IP ranges
            if (request.IpRanges != null && request.IpRanges.Any())
            {
                foreach (var range in request.IpRanges.Where(r => !string.IsNullOrWhiteSpace(r)))
                {
                    ipAddresses.AddRange(_ipRangeService.ParseIpRange(range));
                }
            }
            
            // Check if we have any IP addresses to scan
            if (!ipAddresses.Any())
            {
                return BadRequest("No valid IP addresses provided");
            }
            
            // Remove duplicates
            ipAddresses = ipAddresses.Distinct().ToList();
            
            _logger.LogInformation($"Starting batch scan of {ipAddresses.Count} IP addresses");
            
            // Start the scan
            var results = await _scannerService.ScanMachinesAsync(ipAddresses);
            
            // Return the results
            return Ok(new BatchScanResponse
            {
                TotalIps = ipAddresses.Count,
                ScannedIps = results.Count,
                SuccessfulScans = results.Count(r => r.Status == "success"),
                FailedScans = results.Count(r => r.Status != "success"),
                Results = results
            });
        }
    }
}