#!/usr/bin/env python3

import code

from cib import CIB
from policy import PIB, NEATProperty, NEATPolicy, NEATRequest

POLICY_DIR = "pib/"

if __name__ == "__main__":
    cib = CIB('cib/example/')
    pib = PIB()

    # ----- example from README.md -----
    property1 = NEATProperty(('remote_ip', '10.1.23.45'), precedence=NEATProperty.IMMUTABLE)

    request = NEATRequest()
    request.properties.insert(property1)
    request.properties.insert(NEATProperty(('MTU', (1500, float('inf')))))
    request.properties.insert(NEATProperty(('transport_TCP', True)))

    request.properties

    policy1 = NEATPolicy(name='Bulk transfer')
    policy1.match.insert(NEATProperty(('remote_ip', '10.1.23.45')))
    policy1.properties.insert(NEATProperty(('capacity', (10000, 100000)), precedence=NEATProperty.IMMUTABLE))
    policy1.properties.insert(NEATProperty(('MTU', 9600)))
    pib.register(policy1)

    policy2 = NEATPolicy(name='TCP options')
    policy2.match.insert(NEATProperty(('MTU', 9600)))
    policy2.match.insert(NEATProperty(('is_wired', True)))
    policy2.properties.insert(NEATProperty(('TCP_window_scale', True)))
    pib.register(policy2)

    #code.interact(local=locals(), banner='start')

    print("CIB lookup:")
    cib.lookup(request)
    request.dump()
    #code.interact(local=locals(), banner='CIB lookup done')

    print("PIB lookup:")
    pib.lookup_all(request.candidates)
    request.dump()

    for candidate in request.candidates:
        print(candidate.properties.json())
    code.interact(local=locals(), banner='PIB lookup done')
