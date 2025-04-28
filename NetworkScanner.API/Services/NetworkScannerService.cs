// Services/NetworkScannerService.cs
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Win32;
using NetworkScanner.API.Models;
using System.Diagnostics;

namespace NetworkScanner.API.Services
{
    public class NetworkScannerService
    {
        private readonly string _adminUsername;
        private readonly string _adminPassword;
        private readonly ILogger<NetworkScannerService> _logger;
        private readonly int _defaultMaxConcurrent = 15; // Reduced from 25 for better reliability

        // Ports to scan for common services
        private readonly int[] _portsToScan = new int[] 
        { 
            21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 
            636, 993, 995, 1433, 1434, 3306, 3389, 5900, 5985, 5986, 8080 
        };

        public NetworkScannerService(IConfiguration configuration, ILogger<NetworkScannerService> logger)
        {
            // ADMIN CREDENTIALS: 
            // Option 1: Use appsettings.json (preferred for development)
            _adminUsername = configuration["AdminCredentials:Username"] ?? "admin";
            _adminPassword = configuration["AdminCredentials:Password"] ?? "adminPassword";
            _logger = logger;
            
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
        /// Gets Windows version and release information using WMI
        /// </summary>
        private (string version, string release) GetWindowsInfo(ManagementScope scope)
        {
            string version = "Unknown";
            string release = "Unknown";
            
            try
            {
                // Query for OS information
                ObjectQuery osQuery = new ObjectQuery("SELECT Caption, Version, BuildNumber FROM Win32_OperatingSystem");
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, osQuery))
                {
                    foreach (ManagementObject os in searcher.Get())
                    {
                        // Get basic Windows version information
                        string caption = os["Caption"]?.ToString() ?? "Unknown";
                        
                        // Determine Windows version (10, 11, etc.)
                        if (caption.Contains("Windows 11"))
                        {
                            version = "Windows 11";
                        }
                        else if (caption.Contains("Windows 10"))
                        {
                            version = "Windows 10";
                        }
                        else if (caption.Contains("Windows Server"))
                        {
                            version = caption; // For server versions, use the full caption
                        }
                        else
                        {
                            version = caption;
                        }
                        
                        // Try to get release information
                        try
                        {
                            string machineName = scope.Path.Server;
                            machineName = machineName.Replace("\\\\", "").Replace("\\root\\cimv2", "");
                            
                            // For local machine, use "." instead of IP address
                            if (machineName == ".")
                            {
                                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                                {
                                    if (key != null)
                                    {
                                        // Try DisplayVersion first (Windows 10 20H2 and later)
                                        object displayVersion = key.GetValue("DisplayVersion");
                                        if (displayVersion != null)
                                        {
                                            release = displayVersion.ToString();
                                        }
                                        else
                                        {
                                            // Fall back to ReleaseId (older Windows 10 versions)
                                            object releaseId = key.GetValue("ReleaseId");
                                            if (releaseId != null)
                                            {
                                                release = releaseId.ToString();
                                            }
                                        }
                                    }
                                }
                            }
                            else
                            {
                                // For remote machines, we need to use the registry directly
                                using (RegistryKey baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, machineName))
                                using (RegistryKey key = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                                {
                                    if (key != null)
                                    {
                                        // Try DisplayVersion first (Windows 10 20H2 and later)
                                        object displayVersion = key.GetValue("DisplayVersion");
                                        if (displayVersion != null)
                                        {
                                            release = displayVersion.ToString();
                                        }
                                        else
                                        {
                                            // Fall back to ReleaseId (older Windows 10 versions)
                                            object releaseId = key.GetValue("ReleaseId");
                                            if (releaseId != null)
                                            {
                                                release = releaseId.ToString();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Could not retrieve Windows release information: {ex.Message}");
                        }
                        
                        break; // Only need the first OS entry
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting Windows information: {ex.Message}");
            }
            
            return (version, release);
        }
        
        /// <summary>
        /// Gets Microsoft Office version using registry approach
        /// </summary>
        private string GetOfficeVersion(string machineName)
        {
            // Default message if no Office version found
            string officeVersion = "Not Installed";
            
            // Registry path for installed software
            string registryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            
            // Office-related keywords to search for
            string[] officeKeywords = new[] { "Microsoft Office", "Office 365", "Microsoft 365" };
            
            try
            {
                // Open the remote registry
                using (RegistryKey baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, machineName))
                using (RegistryKey uninstallKey = baseKey.OpenSubKey(registryPath))
                {
                    if (uninstallKey != null)
                    {
                        // Iterate through all installed software registry keys
                        foreach (string subKeyName in uninstallKey.GetSubKeyNames())
                        {
                            using (RegistryKey officeKey = uninstallKey.OpenSubKey(subKeyName))
                            {
                                if (officeKey != null)
                                {
                                    // Get display name and version
                                    string? displayName = officeKey.GetValue("DisplayName") as string;
                                    string? displayVersion = officeKey.GetValue("DisplayVersion") as string;
                                    
                                    if (!string.IsNullOrEmpty(displayName) && !string.IsNullOrEmpty(displayVersion))
                                    {
                                        // Check if this is an Office product (but not Runtime or Tools)
                                        if (officeKeywords.Any(keyword => displayName.Contains(keyword, StringComparison.OrdinalIgnoreCase)) &&
                                            !displayName.Contains("Runtime", StringComparison.OrdinalIgnoreCase) &&
                                            !displayName.Contains("Tools", StringComparison.OrdinalIgnoreCase))
                                        {
                                            officeVersion = $"{displayName} ({displayVersion})";
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // If we encounter an error, return an error message
                officeVersion = $"Error detecting Office version: {ex.Message}";
                _logger.LogError($"Error getting Office version: {ex.Message}");
            }
            
            return officeVersion;
        }
        
        /// <summary>
        /// Gets machine type (manufacturer) and model information
        /// </summary>
        private (string machineType, string machineSku) GetMachineInfo(ManagementScope scope)
        {
            string machineType = "Unknown";
            string machineSku = "Unknown";
            
            try
            {
                // Get manufacturer information
                ObjectQuery manufacturerQuery = new ObjectQuery("SELECT Manufacturer FROM Win32_ComputerSystem");
                using (ManagementObjectSearcher manufacturerSearcher = new ManagementObjectSearcher(scope, manufacturerQuery))
                {
                    foreach (ManagementObject obj in manufacturerSearcher.Get())
                    {
                        machineType = obj["Manufacturer"]?.ToString() ?? "Unknown";
                        break;
                    }
                }
                
                // Get model/SKU information from Win32_ComputerSystemProduct.Version as per previous implementation
                ObjectQuery modelQuery = new ObjectQuery("SELECT Version FROM Win32_ComputerSystemProduct");
                using (ManagementObjectSearcher modelSearcher = new ManagementObjectSearcher(scope, modelQuery))
                {
                    foreach (ManagementObject obj in modelSearcher.Get())
                    {
                        machineSku = obj["Version"]?.ToString() ?? "Unknown";
                        break;
                    }
                }
                
                // If Version didn't give anything useful, try Name as fallback
                if (machineSku == "Unknown" || string.IsNullOrWhiteSpace(machineSku))
                {
                    ObjectQuery nameQuery = new ObjectQuery("SELECT Name FROM Win32_ComputerSystemProduct");
                    using (ManagementObjectSearcher nameSearcher = new ManagementObjectSearcher(scope, nameQuery))
                    {
                        foreach (ManagementObject obj in nameSearcher.Get())
                        {
                            string name = obj["Name"]?.ToString() ?? "Unknown";
                            if (name != "Unknown" && !string.IsNullOrWhiteSpace(name) && name.ToLower() != "system product name")
                            {
                                machineSku = name;
                                break;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting machine information: {ex.Message}");
            }
            
            return (machineType, machineSku);
        }

        /// <summary>
        /// Gets the last logged-in user information
        /// </summary>
        private string GetLastLoggedUser(ManagementScope scope)
        {
            string lastUser = "Unknown";
            
            try
            {
                // Query for the current user
                ObjectQuery userQuery = new ObjectQuery("SELECT UserName FROM Win32_ComputerSystem");
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, userQuery))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        lastUser = obj["UserName"]?.ToString() ?? "Unknown";
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting last logged user: {ex.Message}");
            }
            
            return lastUser;
        }

        /// <summary>
        /// Gets CPU information using WMI
        /// </summary>
        private string GetCpuInfo(ManagementScope scope)
        {
            string cpuInfo = "Unknown";
            
            try
            {
                ObjectQuery cpuQuery = new ObjectQuery("SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor");
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, cpuQuery))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string name = obj["Name"]?.ToString() ?? "Unknown";
                        int cores = Convert.ToInt32(obj["NumberOfCores"]);
                        int logicalProcessors = Convert.ToInt32(obj["NumberOfLogicalProcessors"]);
                        
                        cpuInfo = $"{name}, {cores} cores, {logicalProcessors} logical processors";
                        break; // Just get the first CPU
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting CPU information: {ex.Message}");
            }
            
            return cpuInfo;
        }

        /// <summary>
        /// Gets GPU information using WMI
        /// </summary>
        private string GetGpuInfo(ManagementScope scope)
        {
            string gpuInfo = "Unknown";
            
            try
            {
                ObjectQuery gpuQuery = new ObjectQuery("SELECT Name, AdapterRAM FROM Win32_VideoController");
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, gpuQuery))
                {
                    var gpuList = new List<string>();
                    
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string name = obj["Name"]?.ToString() ?? "Unknown";
                        
                        // Try to get VRAM size
                        string vram = "Unknown VRAM";
                        if (obj["AdapterRAM"] != null)
                        {
                            try
                            {
                                long ramBytes = Convert.ToInt64(obj["AdapterRAM"]);
                                double ramGB = ramBytes / (1024.0 * 1024.0 * 1024.0);
                                vram = $"{ramGB:F2} GB VRAM";
                            }
                            catch
                            {
                                // If conversion fails, just use the name
                            }
                        }
                        
                        gpuList.Add($"{name} ({vram})");
                    }
                    
                    if (gpuList.Count > 0)
                    {
                        gpuInfo = string.Join(" | ", gpuList);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting GPU information: {ex.Message}");
            }
            
            return gpuInfo;
        }

        /// <summary>
        /// Gets disk information using WMI
        /// </summary>
        private (string diskSize, string diskFreeSpace) GetDiskInfo(ManagementScope scope)
        {
            string diskSize = "Unknown";
            string diskFreeSpace = "Unknown";
            
            try
            {
                // Query for logical disks (C: drive)
                ObjectQuery diskQuery = new ObjectQuery("SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DeviceID='C:'");
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, diskQuery))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        // Calculate disk size in GB
                        if (obj["Size"] != null)
                        {
                            double sizeBytes = Convert.ToDouble(obj["Size"]);
                            double sizeGB = sizeBytes / (1024 * 1024 * 1024);
                            diskSize = $"{sizeGB:F2} GB";
                        }
                        
                        // Calculate free space in GB and as percentage
                        if (obj["Size"] != null && obj["FreeSpace"] != null)
                        {
                            double sizeBytes = Convert.ToDouble(obj["Size"]);
                            double freeBytes = Convert.ToDouble(obj["FreeSpace"]);
                            double freeGB = freeBytes / (1024 * 1024 * 1024);
                            double freePercent = (freeBytes / sizeBytes) * 100;
                            
                            diskFreeSpace = $"{freeGB:F2} GB ({freePercent:F1}%)";
                        }
                        
                        break; // Only interested in C: drive
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting disk information: {ex.Message}");
            }
            
            return (diskSize, diskFreeSpace);
        }

        /// <summary>
        /// Gets BIOS version information
        /// </summary>
        private string GetBiosInfo(ManagementScope scope)
        {
            string biosInfo = "Unknown";
            
            try
            {
                ObjectQuery biosQuery = new ObjectQuery("SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS");
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, biosQuery))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string manufacturer = obj["Manufacturer"]?.ToString() ?? "Unknown";
                        string version = obj["SMBIOSBIOSVersion"]?.ToString() ?? "Unknown";
                        string date = "Unknown";
                        
                        // Format the release date if available
                        if (obj["ReleaseDate"] != null)
                        {
                            string rawDate = obj["ReleaseDate"].ToString();
                            // WMI dates are typically in format: YYYYMMDDHHMMSS.mmmmmm+UUU
                            if (rawDate.Length >= 8)
                            {
                                try
                                {
                                    string yearStr = rawDate.Substring(0, 4);
                                    string monthStr = rawDate.Substring(4, 2);
                                    string dayStr = rawDate.Substring(6, 2);
                                    
                                    if (int.TryParse(yearStr, out int year) && 
                                        int.TryParse(monthStr, out int month) && 
                                        int.TryParse(dayStr, out int day))
                                    {
                                        date = $"{month}/{day}/{year}";
                                    }
                                }
                                catch 
                                {
                                    // If parsing fails, leave as Unknown
                                }
                            }
                        }
                        
                        biosInfo = $"{manufacturer} {version} ({date})";
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting BIOS information: {ex.Message}");
            }
            
            return biosInfo;
        }

        /// <summary>
        /// Gets the MAC address of the machine's primary network adapter
        /// </summary>
        private string GetMacAddress(ManagementScope scope)
        {
            string macAddress = "Unknown";
            
            try
            {
                // Query for network adapters that are physical and enabled
                ObjectQuery adapterQuery = new ObjectQuery("SELECT MACAddress FROM Win32_NetworkAdapter WHERE PhysicalAdapter=True AND NetEnabled=True");
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, adapterQuery))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        macAddress = obj["MACAddress"]?.ToString() ?? "Unknown";
                        break; // Just get the first enabled physical adapter
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting MAC address: {ex.Message}");
            }
            
            return macAddress;
        }

        /// <summary>
        /// Scans for open ports on the target machine
        /// </summary>
        private List<int> ScanOpenPorts(string ipAddress)
        {
            var openPorts = new List<int>();
            
            try
            {
                // Create a TCP client
                using (var client = new TcpClient())
                {
                    // Set connection timeout to 100ms for faster scanning
                    client.ReceiveTimeout = 100;
                    client.SendTimeout = 100;
                    
                    // Check each port in our predefined list
                    foreach (int port in _portsToScan)
                    {
                        try
                        {
                            // Start async connection with a short timeout
                            var connectTask = client.ConnectAsync(ipAddress, port);
                            var timeoutTask = Task.Delay(200); // 200ms timeout
                            
                            // Wait for either connection success or timeout
                            var completedTask = Task.WhenAny(connectTask, timeoutTask).Result;
                            
                            // If connection task completed first and didn't throw, the port is open
                            if (completedTask == connectTask && connectTask.IsCompleted && !connectTask.IsFaulted)
                            {
                                openPorts.Add(port);
                            }
                            
                            // Close connection before trying next port
                            client.Close();
                        }
                        catch
                        {
                            // Port is closed or access is denied, continue to next port
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error scanning ports: {ex.Message}");
            }
            
            return openPorts;
        }

        public async Task<ScanResult> ScanMachineAsync(string ipAddress)
        {
            var result = new ScanResult
            {
                IpAddress = ipAddress,
                Status = "pending"
            };

            var stopwatch = Stopwatch.StartNew();

            try
            {
                // Check if we're scanning the local machine
                bool isLocalMachine = IsLocalIpAddress(ipAddress);
                _logger.LogInformation($"Scanning {(isLocalMachine ? "local" : "remote")} machine at {ipAddress}");
                
                // Create scope differently depending on whether it's local or remote
                ManagementScope scope;
                
                // Determine machine name for registry access
                string machineName = isLocalMachine ? "." : ipAddress;
                
                if (isLocalMachine)
                {
                    // For local machine, connect directly using root\cimv2
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
                        EnablePrivileges = true,
                        Timeout = TimeSpan.FromSeconds(10) // Increase from 5 to 10 seconds
                    };

                    // Create management scope for remote connection
                    scope = new ManagementScope($"\\\\{ipAddress}\\root\\cimv2", connectionOptions);
                }
                
                // Connect to WMI with timeout
                var connectTask = Task.Run(() => {
                    try { 
                        scope.Connect(); 
                        return true; 
                    }
                    catch (Exception ex) {
                        _logger.LogWarning($"WMI connection to {ipAddress} failed: {ex.Message}");
                        return false; 
                    }
                });
                
                // Timeout after 10 seconds (increased from 5)
                if (await Task.WhenAny(connectTask, Task.Delay(10000)) != connectTask || !await connectTask)
                {
                    throw new TimeoutException("Connection to WMI timed out");
                }

                // SEQUENTIAL APPROACH FOR CORE DATA
                // Get basic information first (hostname, RAM, etc) sequentially for reliability
                try {
                    // Get hostname information
                    ObjectQuery hostnameQuery = new ObjectQuery("SELECT Name FROM Win32_ComputerSystem");
                    using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, hostnameQuery))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            result.Hostname = obj["Name"]?.ToString() ?? "Unknown";
                            break;
                        }
                    }
                    
                    // Get RAM size information
                    ObjectQuery ramQuery = new ObjectQuery("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
                    using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, ramQuery))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            if (obj["TotalPhysicalMemory"] != null && ulong.TryParse(obj["TotalPhysicalMemory"].ToString(), out ulong totalMemoryBytes))
                            {
                                double totalMemoryGB = totalMemoryBytes / (1024.0 * 1024.0 * 1024.0);
                                result.RamSize = $"{totalMemoryGB:F2} GB";
                            }
                            break;
                        }
                    }
                    
                    // Get Windows version and release information
                    var (windowsVersion, windowsRelease) = GetWindowsInfo(scope);
                    result.WindowsVersion = windowsVersion;
                    result.WindowsRelease = windowsRelease;
                    
                    // Get machine type and model
                    var (machineType, machineSku) = GetMachineInfo(scope);
                    result.MachineType = machineType;
                    result.MachineSku = machineSku;
                    
                    // Get Office version
                    result.OfficeVersion = GetOfficeVersion(machineName);
                }
                catch (Exception ex) {
                    _logger.LogWarning($"Error getting basic information: {ex.Message}");
                }
                
                // PARALLEL APPROACH FOR NON-CRITICAL DATA
                // Run remaining operations in parallel
                var tasks = new List<Task>();
                        
                // Add other independent queries as separate tasks
                tasks.Add(Task.Run(() => {
                    try {
                        result.LastLoggedUser = GetLastLoggedUser(scope);
                    } catch (Exception ex) {
                        _logger.LogWarning($"Error getting last logged user: {ex.Message}");
                    }
                }));
                
                tasks.Add(Task.Run(() => {
                    try {
                        result.CpuInfo = GetCpuInfo(scope);
                    } catch (Exception ex) {
                        _logger.LogWarning($"Error getting CPU info: {ex.Message}");
                    }
                }));
                
                tasks.Add(Task.Run(() => {
                    try {
                        result.GpuInfo = GetGpuInfo(scope);
                    } catch (Exception ex) {
                        _logger.LogWarning($"Error getting GPU info: {ex.Message}");
                    }
                }));
                
                tasks.Add(Task.Run(() => {
                    try {
                        var (diskSize, diskFreeSpace) = GetDiskInfo(scope);
                        result.DiskSize = diskSize;
                        result.DiskFreeSpace = diskFreeSpace;
                    } catch (Exception ex) {
                        _logger.LogWarning($"Error getting disk info: {ex.Message}");
                    }
                }));
                
                tasks.Add(Task.Run(() => {
                    try {
                        result.BiosVersion = GetBiosInfo(scope);
                    } catch (Exception ex) {
                        _logger.LogWarning($"Error getting BIOS info: {ex.Message}");
                    }
                }));
                
                tasks.Add(Task.Run(() => {
                    try {
                        result.MacAddress = GetMacAddress(scope);
                    } catch (Exception ex) {
                        _logger.LogWarning($"Error getting MAC address: {ex.Message}");
                    }
                }));
                
                tasks.Add(Task.Run(() => {
                    try {
                        result.OpenPorts = ScanOpenPorts(ipAddress);
                    } catch (Exception ex) {
                        _logger.LogWarning($"Error scanning ports: {ex.Message}");
                    }
                }));
                
                // Wait for all tasks to complete with a timeout
                var timeoutTask = Task.Delay(20000); // Increased from 15 to 20 seconds
                if (await Task.WhenAny(Task.WhenAll(tasks), timeoutTask) == timeoutTask)
                {
                    _logger.LogWarning($"Some tasks timed out for {ipAddress}");
                }
                
                stopwatch.Stop();
                var elapsedMs = stopwatch.ElapsedMilliseconds;
                result.ScanTimeMs = elapsedMs;
                _logger.LogInformation($"Scan completed in {elapsedMs}ms for {ipAddress}");

                // Set success status if we reach this point
                result.Status = "success";
            }
            catch (Exception ex)
            {
                // Handle any errors that occurred during scanning
                result.Status = "error";
                result.ErrorMessage = ex.Message;
                stopwatch.Stop();
                result.ScanTimeMs = stopwatch.ElapsedMilliseconds;
                _logger.LogError($"Error scanning {ipAddress}: {ex.Message}");
            }

            return result;
        }

        // Add the original ScanMachine method to maintain compatibility
        public ScanResult ScanMachine(string ipAddress)
        {
            return ScanMachineAsync(ipAddress).GetAwaiter().GetResult();
        }

        // ScanMachinesAsync method 
        public async Task<List<ScanResult>> ScanMachinesAsync(
            IEnumerable<string> ipAddresses, 
            int maxConcurrent = 0, // Changed default to 0 to use _defaultMaxConcurrent
            IProgress<BatchScanResponse>? progress = null)
        {
            if (maxConcurrent <= 0)
                maxConcurrent = _defaultMaxConcurrent;
                
            var results = new List<ScanResult>();
            var totalIps = ipAddresses.Count();
            var scannedIps = 0;
            var successfulScans = 0;
            var failedScans = 0;
            
            // Create a semaphore to limit concurrent operations
            using var semaphore = new SemaphoreSlim(maxConcurrent);
            
            // Create a list of tasks
            var tasks = new List<Task<ScanResult>>();
            
            // Create a timer to report progress more frequently (every 250ms)
            using var progressTimer = new Timer(_ => 
            {
                progress?.Report(new BatchScanResponse
                {
                    TotalIps = totalIps,
                    ScannedIps = scannedIps,
                    SuccessfulScans = successfulScans,
                    FailedScans = failedScans,
                    Results = new List<ScanResult>(results)
                });
            }, null, 0, 250);
            
            // Start scanning each IP address
            foreach (var ipAddress in ipAddresses)
            {
                // Wait for a slot in the semaphore
                await semaphore.WaitAsync();
                
                // Start the scan
                tasks.Add(Task.Run(async () => 
                {
                    try
                    {
                        // Scan the machine
                        var result = await ScanMachineAsync(ipAddress);
                        
                        // Update counters
                        Interlocked.Increment(ref scannedIps);
                        if (result.Status == "success")
                            Interlocked.Increment(ref successfulScans);
                        else
                            Interlocked.Increment(ref failedScans);
                        
                        // Add the result to the list
                        lock (results)
                        {
                            results.Add(result);
                        }
                        
                        // Report progress immediately after each scan
                        progress?.Report(new BatchScanResponse
                        {
                            TotalIps = totalIps,
                            ScannedIps = scannedIps,
                            SuccessfulScans = successfulScans,
                            FailedScans = failedScans,
                            Results = new List<ScanResult>(results)
                        });
                        
                        return result;
                    }
                    finally
                    {
                        // Release the semaphore slot
                        semaphore.Release();
                    }
                }));
            }
            
            // Wait for all tasks to complete
            await Task.WhenAll(tasks);
            
            // Report final progress
            progress?.Report(new BatchScanResponse
            {
                TotalIps = totalIps,
                ScannedIps = scannedIps,
                SuccessfulScans = successfulScans,
                FailedScans = failedScans,
                Results = new List<ScanResult>(results)
            });
            
            return results;
        }
    }  
}