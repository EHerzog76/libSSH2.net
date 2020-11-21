using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace TestSSH
{
    /// <summary>
    /// <en>
    /// Decide the priority level of IPv4 and IPv6
    /// </en>
    /// </summary>
    //[EnumDesc(typeof(IPVersionPriority))]
    public enum IPVersionPriority
    {
        /// <summary>
        /// <en>Both IPv4 and IPv6 are used.</en>
        /// </summary>
        //[EnumValue(Description="Enum.IPVersionPriority.Both")]
        Both,
        /// <summary>
        /// <en>Only IPv4 is used.</en>
        /// </summary>
        //[EnumValue(Description="Enum.IPVersionPriority.V4Only")]
        V4Only,
        /// <summary>
        /// <en>Only IPv6 is used.</en>
        /// </summary>
        //[EnumValue(Description="Enum.IPVersionPriority.V6Only")]
        V6Only
    }

    //V4 / V6
    public class IPAddressList
    {
        private IPAddress[] _addresses;

        public IPAddressList(string host)
        {
            _addresses = Dns.GetHostAddresses(host);
        }
        public IPAddressList(IPAddress a)
        {
            _addresses = new IPAddress[] { a };
        }
        public IPAddressList(IPAddress v4, IPAddress v6)
        {
            _addresses = new IPAddress[] { v4, v6 };
        }
        public IPAddressList(IPAddress[] addresses)
        {
            _addresses = addresses;
        }
        
        //V4,6
        public IPAddress[] AvailableAddresses
        {
            get
            {
                IPVersionPriority pr = IPVersionPriority.Both;
                if (pr == IPVersionPriority.Both) return _addresses;

                List<IPAddress> result = new List<IPAddress>();
                foreach (IPAddress a in _addresses)
                {
                    if (pr == IPVersionPriority.V6Only && a.AddressFamily == AddressFamily.InterNetworkV6) result.Add(a);
                    else if (pr == IPVersionPriority.V4Only && a.AddressFamily == AddressFamily.InterNetwork) result.Add(a);
                }
                return result.ToArray();
            }
        }

        //Check host is ip or name and return the IP-Address
        public static IPAddressList SilentGetAddress(string host)
        {
            IPAddress address;
            if (IPAddress.TryParse(host, out address))
                return new IPAddressList(address);
            else
            {
                try
                {
                    return new IPAddressList(host);
                }
                catch (Exception)
                {
                    return new IPAddressList(new IPAddress[0]);
                }
            }
        }
    }
}
