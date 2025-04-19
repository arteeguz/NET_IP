// Services/NetworkScannerService.cs
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetworkScanner.API.Models;

namespace NetworkScanner.API.Services
{
    public class NetworkScannerService
    {
        private readonly string _adminUsername;
        private readonly string _adminPassword;

        public NetworkScannerService(IConfiguration configuration)
        {
            // ADMIN CREDENTIALS: 
            // Option 1: Use appsettings.json (preferred for development)
            _adminUsername = configuration["AdminCredentials:Username"] ?? "admin";
            _adminPassword = configuration["AdminCredentials:Password"] ?? "adminPassword";
            
            // Option 2: Hard-code credentials (not recommended, but simple)
            // _adminUsername = "domain\\adminuser"; // Use actual domain admin user
            // _adminPassword = "actualPassword";    // Use actual password
            
            // Option 3: Environment variables (good for production)
            // _adminUsername = Environment.GetEnvironmentVariable("SCANNER_ADMIN_USER") ?? "admin";
            // _adminPassword = Environment.GetEnvironmentVariable("SCANNER_ADMIN_PASS") ?? "adminPassword";
        }

        /// <summary>
        /// Determines if an IP address belongs to the local machine
        /// </summary>
        private bool IsLocalIpAddress(string ipAddress)
        {
            // Check if localhost
            if (ipAddress.Equals("localhost", StringComparison.OrdinalIgnoreCase) || 
                ipAddress.Equals("127.0.0.1"))
                return true;

            try
            {
                // Get all IP addresses assigned to local network interfaces
                IPAddress[] localIPs = Dns.GetHostAddresses(Dns.GetHostName());
                
                // Parse the input IP
                if (IPAddress.TryParse(ipAddress, out IPAddress ipToCheck))
                {
                    // Check if the IP exists in the local IP list
                    foreach (IPAddress localIP in localIPs)
                    {
                        if (ipToCheck.Equals(localIP))
                            return true;
                    }
                }
            }
            catch
            {
                // In case of any errors, assume it's not local
                return false;
            }
            
            return false;
        }

        /// <summary>
        /// Scans a Windows machine and retrieves basic system information
        /// </summary>
        public ScanResult ScanMachine(string ipAddress)
        {
            var result = new ScanResult
            {
                IpAddress = ipAddress,
                Status = "pending"
            };

            try
            {
                // Check if we're scanning the local machine
                bool isLocalMachine = IsLocalIpAddress(ipAddress);
                
                // Create scope differently depending on whether it's local or remote
                ManagementScope scope;
                
                if (isLocalMachine)
                {
                    // For local machine, connect directly using root\cimv2
                    // Note: We use the dot notation which works better for local connections
                    scope = new ManagementScope(@"\\.\root\cimv2");
                }
                else
                {
                    // Set up connection options with admin credentials for WMI
                    ConnectionOptions connectionOptions = new ConnectionOptions
                    {
                        Username = _adminUsername,
                        Password = _adminPassword,
                        Impersonation = ImpersonationLevel.Impersonate,
                        Authentication = AuthenticationLevel.PacketPrivacy,
                        EnablePrivileges = true
                    };

                    // Create management scope for remote connection
                    scope = new ManagementScope($"\\\\{ipAddress}\\root\\cimv2", connectionOptions);
                }
                
                // Connect to WMI
                scope.Connect();

                // Get hostname information from the remote machine
                ObjectQuery hostnameQuery = new ObjectQuery("SELECT Name FROM Win32_ComputerSystem");
                ManagementObjectSearcher hostnameSearcher = new ManagementObjectSearcher(scope, hostnameQuery);
                foreach (ManagementObject obj in hostnameSearcher.Get())
                {
                    result.Hostname = obj["Name"]?.ToString();
                    break;
                }

                // Get RAM size information from the remote machine
                ObjectQuery ramQuery = new ObjectQuery("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
                ManagementObjectSearcher ramSearcher = new ManagementObjectSearcher(scope, ramQuery);
                foreach (ManagementObject obj in ramSearcher.Get())
                {
                    if (obj["TotalPhysicalMemory"] != null && ulong.TryParse(obj["TotalPhysicalMemory"].ToString(), out ulong totalMemoryBytes))
                    {
                        double totalMemoryGB = totalMemoryBytes / (1024.0 * 1024.0 * 1024.0);
                        result.RamSize = $"{totalMemoryGB:F2} GB";
                    }
                    break;
                }

                // Set success status if we reach this point
                result.Status = "success";
            }
            catch (Exception ex)
            {
                // Handle any errors that occurred during scanning
                result.Status = "error";
                result.ErrorMessage = ex.Message;
            }

            return result;
        }
    }
}