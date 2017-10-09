import urllib.request
import json
import netifaces

from pyroute2 import IPRoute

from ipaddress import IPv4Network, IPv4Address
import pmdefaults as PM
import cib
from policy import NEATProperty, PropertyArray

def interfaceforremoteaddress(addr):
    with IPRoute() as ipr:
        for attr in ipr.route('get', dst=addr)[0]['attrs']:
            if attr[0] == 'RTA_PREFSRC':
               local_addr = attr[1]
               break
    for iface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(iface)
        for k, v in addresses.items():
            if v[0]['addr'] == local_addr:
                return iface, local_addr
    return None

def gen_cibs(hosts):
    for host in hosts:
        uri = "http://{}:8080/pvd-all.json".format(host)

        #look up our local interface in the routing table
        en, local_addr  = interfaceforremoteaddress(host)    
        print("local interface {}".format(en))

        c = cib.CIBNode()
        c.uid = "pvd-{}-{}".format(en, host)
        #c.match = {"uid": {"value": en}}   
        #c.match = en
        c.description = "PvD CIB node for remote host {}".format(host)
        c.link = True
        c.filename = c.uid + '.cib'
        c.expire = -1 # TODO: this is in the pvd data, please set

        pa = PropertyArray()
        pa.add(NEATProperty(('interface', en), precedence=NEATProperty.IMMUTABLE))
        pa.add(NEATProperty(('local_interface', True), precedence=NEATProperty.IMMUTABLE))
        c.properties.add(pa)

        data = urllib.request.urlopen(uri).read().decode('utf8')
        data = json.loads(data)

        properties = pvdcharacteristicstoneatproperties(
            data['pvd.cisco.com']['attributes']['extraInfo']['characteristics']
        )

        c.properties.add(properties)
        yield c.json()

def pvdcharacteristicstoneatproperties(chars):
    p2p = { 
        'minLatency':'RTT',
        'maxThroughput':'capacity'
    }
    res = {}

    pa = PropertyArray()

    for k,v in chars.items():
        if k in p2p:
            pa.add(NEATProperty(
                (p2p[k], next (iter (chars[k].values()))), 
                precedence=NEATProperty.IMMUTABLE)
            )
    return pa

if __name__ == "__main__":
    hosts = ["192.168.56.10"]
    for x in gen_cibs(hosts):
        print(x)
