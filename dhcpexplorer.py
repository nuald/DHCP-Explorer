#!/usr/bin/env python

"""
DHCP explorer. Finds all DHCP servers in local network
"""

from optparse import OptionParser
from scapy.all import conf, get_if_raw_hwaddr, Ether, IP, UDP, BOOTP, DHCP, srp


def main():
    """
        Entry point
    """
    # Parsing command line
    parser = OptionParser()
    parser.add_option("-t", "--timeout", type="float", dest="timeout",
                      default=1,
                      help="timeout in seconds for waiting answers",
                      metavar="TIME")
    (options, args) = parser.parse_args()

    conf.checkIPaddr = False
    fam, hw = get_if_raw_hwaddr(conf.iface)
    mac = ":".join(map(lambda x: "%.02x" % ord(x), list(hw)))
    print 'Requesting DHCP servers for', mac
    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=hw)
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(chaddr=hw)
    dhcp = DHCP(options=[("message-type", "discover"), "end"])
    dhcp_discover = ether / ip / udp / bootp / dhcp
    ans, unans = srp(dhcp_discover, multi=True, timeout=options.timeout)
    print 'Discovered DHCP servers:'
    for p in ans:
        print p[1][Ether].src, p[1][IP].src

if __name__ == '__main__':
    main()
