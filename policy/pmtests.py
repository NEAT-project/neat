#!/usr/bin/env python3.5

from policy import *
import sys
import locale
import codecs

locale.setlocale(locale.LC_ALL, ('en', 'utf-8'))

logging.basicConfig(format='[%(levelname)s]: %(message)s', level=logging.DEBUG)


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

        np3 = NEATProperty(("MTU", {"start": 50, "end": 1000}), score=1)
        np4 = NEATProperty(("MTU", 100), score=1)
        np3.update(np4)
        self.assertEqual(np3.value, 100)
        self.assertEqual(np3.score, 2)

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
        np1 = NEATProperty(("MTU", None), score=1, precedence=NEATProperty.IMMUTABLE)

        np2 = NEATProperty(("MTU", "lala"), score=1, precedence=NEATProperty.OPTIONAL)
        np3 = NEATProperty(("MTU", "lolo"), score=1, precedence=NEATProperty.OPTIONAL)

        self.assertEqual(np2 & np3, False)
        self.assertEqual(np1 & np2, False)

    def test_property_array_creation(self):
        np1 = NEATProperty(("MTU", {"start": 50, "end": 1000}))
        np2 = NEATProperty(("MTU", 10000))
        np3 = NEATProperty(("MTU", [1000, 9000]))
        np4 = NEATProperty(('foo', 'bar'))
        np5 = NEATProperty(('foo', 'bas'))

        pd1 = PropertyArray()
        pd2 = PropertyArray()
        pd1.add(np3)
        pd1.add(np1, np2)
        pd2.add(np4, np5, NEATProperty(('moo', 'bar')))
        print(pd1)
        self.assertEqual(pd1['MTU'].value, 10000)
        self.assertEqual(pd2['foo'].value, 'bas')
        self.assertEqual(len(pd1 + pd2), 3)
        self.assertEqual(len(pd1 & pd2), 0)

    def test_property_multi_array_creation(self):
        test_request_str = '[{"remote_ip": {"precedence": 2, "value": "10:54:1.23"}, "transport": [{"value": "TCP", "banned": ["UDP", "UDPLite"]}, {"value": "UDP"}], "MTU": {"value": [1500, 9000]}, "low_latency": {"precedence": 2, "value": true}, "foo": {"banned": ["baz"]}}]'
        req = json_to_properties(test_request_str)
        pma = PropertyMultiArray()
        for p in req[0]:
            pma.add(p)
        print(pma)

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

if __name__ == "__main__":
    print(sys.stdout.encoding)
    print(locale.getpreferredencoding())
    unittest.main()
