#!/usr/bin/env python3

import code

from cib import CIB
from policy import PIB, NEATCandidate, NEATProperty, NEATPolicy, NEATRequest, NEATPropertyError

POLICY_DIR = "pib/"

if __name__ == "__main__":
    cib = CIB()
    cib.load_cib('cib/example/')
    pib = PIB()

    # ----- example from README.md -----
    request = NEATRequest()
    request.properties.insert(NEATProperty(('remote_ip', '10.1.23.45'), level=NEATProperty.IMMUTABLE))
    request.properties.insert(NEATProperty(('MTU', (1500, float('inf')))))
    request.properties.insert(NEATProperty(('transport', 'TCP')))

    request.properties

    policy1 = NEATPolicy(name='Bulk transfer')
    policy1.match.insert(NEATProperty(('remote_ip', '10.1.23.45')))
    policy1.properties.insert(NEATProperty(('capacity', (10, 100)), level=NEATProperty.IMMUTABLE))
    policy1.properties.insert(NEATProperty(('MTU', 9600)))
    pib.register(policy1)

    policy2 = NEATPolicy(name='TCP options')
    policy2.match.insert(NEATProperty(('MTU', 9600)))
    policy2.match.insert(NEATProperty(('is_wired', True)))
    policy2.properties.insert(NEATProperty(('TCP_window_scale', True)))
    pib.register(policy2)

    #code.interact(local=locals(), banner='start')

    print("PIB lookup:")
    cib.lookup(request)
    request.dump()
    #code.interact(local=locals(), banner='CIB lookup done')

    print("PIB lookup:")
    pib.lookup_all(request.candidates)
    request.dump()
    #code.interact(local=locals(), banner='PIB lookup done')
