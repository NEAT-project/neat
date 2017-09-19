#!/usr/bin/env python3.5

import locale
import socket
import unittest

from policy import *

locale.setlocale(locale.LC_ALL, ('en', 'utf-8'))

def gen_test_request():
    test_request_str = '[{"remote_ip": {"precedence": 2,"value": "10.54.1.23"}, "port": {"precedence": 2, "value": 8080}, "__pre_resolve": {"value": true}, "transport": {"value": "reliable"}, "MTU": {"value": [1500, 9000]}, "low_latency": {"precedence": 1, "value": true}}]'
    
class PropertyTests(unittest.TestCase):
    # TODO extend tests

    def test_property_logic(self):
        np1 = NEATProperty(('foo', 'bar'), precedence=NEATProperty.OPTIONAL)
        np2 = NEATProperty(('foo', 'bas'), precedence=NEATProperty.IMMUTABLE)
        np3 = NEATProperty(('foo', 'bat'), precedence=NEATProperty.IMMUTABLE)

        np1.update(np2)
        self.assertEqual(np1.value, np2.value)
        self.assertEqual(np1.precedence, np2.precedence)

        with self.assertRaises(ImmutablePropertyError):
            np3.update(np2)

    def test_ranges(self):
        np1 = NEATProperty(("MTU", {"start": 50, "end": 1000}), score=1)
        np2 = NEATProperty(("MTU", 9000), score=1)
        np1.update(np2)
        self.assertEqual(np1.value, 9000)
        self.assertEqual(np1.score, 1)

        np1 = NEATProperty(("MTU", {"start": 50, "end": 1000}), score=1)
        np2 = NEATProperty(("MTU", 100), score=1)
        np1.update(np2)
        self.assertEqual(np1.value, 100)
        self.assertEqual(np1.score, 2)

        np1 = NEATProperty(("MTU", {"start": 50, "end": 1000}), score=1)
        np2 = NEATProperty(("MTU", [100, 500, 9000]), score=1)
        np1.update(np2)
        self.assertEqual(np1.value, {100, 500})
        self.assertEqual(np1.score, 2)

    def test_sets(self):
        np1 = NEATProperty(("MTU", {"start": 50, "end": 1000}), score=1, precedence=NEATProperty.IMMUTABLE)
        np2 = NEATProperty(("MTU", [9000, 100, 1000]), score=1, precedence=NEATProperty.IMMUTABLE)

        np1.update(np2)
        self.assertEqual(np1.value, {1000, 100})

        np3 = NEATProperty(("MTU", {"start": 50, "end": 1000}), score=1, precedence=NEATProperty.IMMUTABLE)
        np4 = NEATProperty(("MTU", [55, 9000]), score=1, precedence=NEATProperty.IMMUTABLE)

        np3.update(np4)
        self.assertEqual(np3.value, 55)

    def test_empty_value(self):
        # None essentially means ANY
        np1 = NEATProperty(("MTU", None), score=1, precedence=NEATProperty.IMMUTABLE)

        np2 = NEATProperty(("MTU", "foo"), score=1, precedence=NEATProperty.OPTIONAL)
        np3 = NEATProperty(("MTU", "bar"), score=1, precedence=NEATProperty.OPTIONAL)
        self.assertEqual(np2 & np3, False)

        # np1 should match any property
        self.assertNotEqual(np1 & np2, False)

    def test_property_array_creation(self):
        np1 = NEATProperty(("MTU", {"start": 50, "end": 1000}))
        np2 = NEATProperty(("MTU", 10000))
        np3 = NEATProperty(("MTU", [1000, 9000]))
        np4 = NEATProperty(('foo', 'bar'))
        np5 = NEATProperty(('foo', 'bas'))

        pa1 = PropertyArray()
        pa1.add(np3)
        pa1.add(np1, np2)

        pa2 = PropertyArray()
        pa2.add(np4, np5, NEATProperty(('moo', 'bar')))
        print(pa1)

        # properties names use lower case internally
        self.assertEqual(pa1['mtu'].value, 10000)
        self.assertEqual(pa2['foo'].value, 'bas')
        self.assertEqual(len(pa1 + pa2), 3)
        self.assertEqual(len(pa1 & pa2), 0)

    def test_property_multi_array_creation(self):
        test_request_str = '[{"remote_ip": {"precedence": 2, "value": "10:54:1.23"}, "transport": [{"value": "TCP", "banned": ["UDP", "UDPLite"]}, {"value": "UDP"}], "MTU": {"value": [1500, 9000]}, "low_latency": {"precedence": 2, "value": true}, "foo": {"banned": ["baz"]}}]'
        req = json_to_properties(test_request_str)
        pma = PropertyMultiArray()
        for p in req[0]:
            pma.add(p)
        print(pma)

    def test_property_nested_arrays(self):
        pa = PropertyArray()

        test_request_str = '[{"remote_ip": {"precedence": 2, "value": "10:54:1.23"}, [{"transport": ["value": "TCP"}}], "MTU": {"value": [1500, 9000]}, "low_latency": {"precedence": 2, "value": true}, "foo": {"banned": ["baz"]}}]'
        pma = PropertyMultiArray()

        #import code
        #code.interact(banner='>>> test here:', local=dict(globals(), **locals()))

    def test_property_multi_array_creation_RENAME(self):
        """multiple requests (list)"""
        test_request_str = '[{"remote_ip": {"precedence": 2, "value": "10:54:1.23"}, "transport": [{"value": "TCP", "banned": ["UDP", "UDPLite"]}, {"value": "UDP"}]},  {"MTU": {"value": [1500, 9000]}, "low_latency": {"precedence": 2, "value": true}, "foo": {"banned": ["baz"]}}]'
        req = json_to_properties(test_request_str)
        pma_list = []
        for r in req:
            pma = PropertyMultiArray()
            for property in r:
                pma.add(property)
            print(pma)
            pma_list.append(pma)

    def test_default_pib_cib(self):
        import pmdefaults as PM

        # TODO
        test_request_str = '[{"remote_ip": {"precedence": 2,"value": "10.54.1.23"}, "port": {"precedence": 2, "value": 8080}, "__pre_resolve": {"value": true}, "transport": {"value": "reliable"}, "MTU": {"value": [1500, 9000]}, "low_latency": {"precedence": 1, "value": true}}]'

        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1)  # 1 second timeout, after all it should be instant because its local
        try:
            s.connect(PM.DOMAIN_SOCK)
        except (FileNotFoundError, ConnectionRefusedError) as e:
            print("PM: " + e.args[1])
            s.close()
            return

        print('Connected to PM on %s' % PM.DOMAIN_SOCK)
        print("REQUEST:")
        print(test_request_str)
        s.send(test_request_str.encode())
        s.shutdown(socket.SHUT_WR)

        resp = s.recv(8192)
        s.close()
        print("REPLY:")
        jresp = json.loads(resp.decode())
        for r in jresp:
            print(PropertyArray.from_dict(r))
        print("\n")


if __name__ == "__main__":
    print(sys.stdout.encoding)
    print(locale.getpreferredencoding())
    unittest.main()
