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
        private readonly ILogger<ScannerController> _logger;

        public ScannerController(NetworkScannerService scannerService, ILogger<ScannerController> logger)
        {
            _scannerService = scannerService;
            _logger = logger;
        }

        /// <summary>
        /// Endpoint to scan a machine by IP address
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
    }
}