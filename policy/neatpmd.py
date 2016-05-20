#!/usr/bin/env python3

import code

from cib import CIB
from policy import PIB, NEATCandidate, NEATProperty, NEATPolicy, NEATRequest, NEATPropertyError

POLICY_DIR = "pib/"

if __name__ == "__main__":
    pib = PIB()
    pib.load_policies()

    cib = CIB()
    cib.load_cib()

    print(pib)
    print(cib)

    C = {"name": "C", "description": "foo and bar", "priority": "0",
         "match": {"requested": {'foo': 'bar'}},
         "properties": {"immutable": {'foo3': 'bar3'}}}

    p = NEATPolicy(name="dynamic")
    p.match.update({"is_wired_interface": True}.items())
    p.properties.update([("TCP_CC", "cubic", NEATProperty.IMMUTABLE), ("MTU", "9600")])

    pib.register(p)

    query = NEATRequest(requested={'remote_address': '23:::23:12', 'foo': 'bar'},
                        immutable={'MTU': 9600, "is_wired_interface": True},
                        informational={'low_latency': True})

    # lookup CIB
    code.interact(local=locals())
    cib.lookup(query)
    code.interact(local=locals(), banner='CIB lookup done')

    nc = query.candidates[0]

    query.dump()

    pib.lookup_all(query.candidates)

    code.interact(local=locals(), banner='PIB lookup done')
    query.dump()

    # ----- example from README -----
    request = NEATRequest()
    request.properties.insert(NEATProperty(('remote_ip', '10.1.23.45'), level=NEATProperty.IMMUTABLE))
    request.properties.insert(NEATProperty(('MTU', (1500, float('inf')))))
    request.properties.insert(NEATProperty(('transport', 'TCP')))

    request.properties

    policy1 = NEATPolicy(name='Bulk transfer')
    policy1.match.insert(NEATProperty(('remote_ip', '10.1.23.45')))
    policy1.properties.insert(NEATProperty(('capacity', (10, 100))))
    policy1.properties.insert(NEATProperty(('MTU', 9600)))

    policy2 = NEATPolicy(name='TCP options')
    policy2.match.insert(NEATProperty(('MTU', 9600)))
    policy2.match.insert(NEATProperty(('is_wired', True)))
    policy2.properties.insert(NEATProperty(('TCP_window_scale', True)))

    ###########
    nc = NEATCandidate(query)
    # for i in query.items():
    #    nc.properties.add(NEATProperty(i))
    c = cib.entries['s3']
