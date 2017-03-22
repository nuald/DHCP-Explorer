#!/usr/bin/env python

"""
DHCP explorer. Finds all DHCP servers in local network
"""

from scapy.all import conf, get_if_raw_hwaddr, Ether, IP, UDP, BOOTP, DHCP, srp


def main():
    """
        Entry point
    """
    conf.checkIPaddr = False
    fam, hw = get_if_raw_hwaddr(conf.iface)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(chaddr=hw)
    dhcp = DHCP(options=[("message-type", "discover"), "end"])
    dhcp_discover = ether / ip / udp / bootp / dhcp
    ans, unans = srp(dhcp_discover, multi=False)
    for p in ans:
        print p[1][Ether].src, p[1][IP].src

if __name__ == '__main__':
    main()
