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

    # lookup PIB
    for candidate in query.candidates:
        try:
            pib.lookup(candidate, apply=True)
        except NEATPropertyError:
            candidate.invalid = True
            i = query.candidates.index(candidate)
            print('Candidate %d is invalidated due to policy' % i)
    for candidate in query.candidates:
        if candidate.invalid:
            query.candidates.remove(candidate)

    code.interact(local=locals(), banner='PIB lookup done')
    query.dump()

    ###########
    nc = NEATCandidate(query)
    # for i in query.items():
    #    nc.properties.add(NEATProperty(i))
    c = cib.entries['s3']
