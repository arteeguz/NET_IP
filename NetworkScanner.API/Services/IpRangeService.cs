// Services/IpRangeService.cs
using System.Net;
using System.Net.Sockets;

namespace NetworkScanner.API.Services
{
    public class IpRangeService
    {
        /// <summary>
        /// Parses an IP range string and returns a list of IP addresses
        /// </summary>
        /// <param name="ipRange">IP range in format "192.168.1.1-192.168.1.254" or "192.168.1.0/24"</param>
        /// <returns>List of IP addresses in the range</returns>
        public List<string> ParseIpRange(string ipRange)
        {
            var ipAddresses = new List<string>();
            
            if (string.IsNullOrWhiteSpace(ipRange))
                return ipAddresses;
            
            // Check if CIDR notation (e.g., 192.168.1.0/24)
            if (ipRange.Contains("/"))
            {
                ipAddresses.AddRange(ParseCidrRange(ipRange));
            }
            // Check if range notation (e.g., 192.168.1.1-192.168.1.254)
            else if (ipRange.Contains("-"))
            {
                ipAddresses.AddRange(ParseDashRange(ipRange));
            }
            // Single IP
            else if (IPAddress.TryParse(ipRange, out _))
            {
                ipAddresses.Add(ipRange);
            }
            
            return ipAddresses;
        }
        
        /// <summary>
        /// Parses a CIDR notation IP range (e.g., 192.168.1.0/24)
        /// </summary>
        private List<string> ParseCidrRange(string cidrRange)
        {
            var ipAddresses = new List<string>();
            
            try
            {
                string[] parts = cidrRange.Split('/');
                if (parts.Length != 2)
                    return ipAddresses;
                
                if (!IPAddress.TryParse(parts[0], out IPAddress address))
                    return ipAddresses;
                
                if (!int.TryParse(parts[1], out int prefixLength) || prefixLength < 0 || prefixLength > 32)
                    return ipAddresses;
                
                // Convert IP address to bytes
                byte[] ipBytes = address.GetAddressBytes();
                
                // Calculate the network mask from the prefix length
                uint mask = ~(uint.MaxValue >> prefixLength);
                
                // Calculate the network address
                uint network = BitConverter.ToUInt32(ipBytes.Reverse().ToArray(), 0) & mask;
                
                // Calculate the broadcast address
                uint broadcast = network | ~mask;
                
                // Generate all IP addresses between network and broadcast
                for (uint i = network + 1; i < broadcast; i++)
                {
                    byte[] bytes = BitConverter.GetBytes(i).Reverse().ToArray();
                    ipAddresses.Add(new IPAddress(bytes).ToString());
                }
            }
            catch (Exception)
            {
                // Return an empty list if any error occurs
                return new List<string>();
            }
            
            return ipAddresses;
        }
        
        /// <summary>
        /// Parses a dash-notation IP range (e.g., 192.168.1.1-192.168.1.254)
        /// </summary>
        private List<string> ParseDashRange(string dashRange)
        {
            var ipAddresses = new List<string>();
            
            try
            {
                string[] parts = dashRange.Split('-');
                if (parts.Length != 2)
                    return ipAddresses;
                
                if (!IPAddress.TryParse(parts[0], out IPAddress startAddress) || 
                    !IPAddress.TryParse(parts[1], out IPAddress endAddress))
                    return ipAddresses;
                
                // Ensure both IPs are IPv4
                if (startAddress.AddressFamily != AddressFamily.InterNetwork ||
                    endAddress.AddressFamily != AddressFamily.InterNetwork)
                    return ipAddresses;
                
                // Convert to integers for comparison
                uint startIp = BitConverter.ToUInt32(startAddress.GetAddressBytes().Reverse().ToArray(), 0);
                uint endIp = BitConverter.ToUInt32(endAddress.GetAddressBytes().Reverse().ToArray(), 0);
                
                // Ensure start IP is less than or equal to end IP
                if (startIp > endIp)
                    return ipAddresses;
                
                // Generate all IP addresses between start and end (inclusive)
                for (uint i = startIp; i <= endIp; i++)
                {
                    byte[] bytes = BitConverter.GetBytes(i).Reverse().ToArray();
                    ipAddresses.Add(new IPAddress(bytes).ToString());
                }
            }
            catch (Exception)
            {
                // Return an empty list if any error occurs
                return new List<string>();
            }
            
            return ipAddresses;
        }
    }
}