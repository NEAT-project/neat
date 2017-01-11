import netifaces
from ipaddress import IPv4Network, IPv4Address

# Builds a ip network object given an input ip address and netmask
def get_network_address(ip, netmask):
    ip = IPv4Address(ip)
    netmask = IPv4Address(netmask)
    net_ip = IPv4Address(int(ip) & int(netmask))
    return IPv4Network('%s/%s' % (net_ip, netmask))


def get_if(ipaddr):
    ipaddr = IPv4Address(ipaddr)
    for en in netifaces.interfaces():
        for addr in netifaces.ifaddresses(en).get(netifaces.AF_INET, []):
            try:
                net = get_network_address(addr['addr'], addr['netmask'])
                if ipaddr in net:
                    return addr['addr']
            except ValueError as e:
                pass
    gw, en = netifaces.gateways()['default'][netifaces.AF_INET]
    return netifaces.ifaddresses(en)[netifaces.AF_INET][0]['addr']