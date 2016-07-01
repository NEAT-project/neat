import logging
import os
import operator
import json

from collections import ChainMap

from policy import NEATPolicy, NEATRequest, NEATCandidate, NEATProperty, PropertyDict, NEATPropertyError, numeric

logging.basicConfig(format='[%(levelname)s]: %(message)s', level=logging.DEBUG)

LOCAL = 'local'
CONNECTION = 'connection'
REMOTE = 'remote'
ENTRIES = 'entries'


class CIB(object):
    """Internal representation of the CIB for testing"""

    # We don't care about some of the CIB properties for matching. Define these special keys here
    meta_keys = {'id', 'type', 'remote', 'local', 'filename', 'cib_source', 'timestamp', 'connection'}

    def __init__(self, cib_dir=None):

        # define three repository types for CIB sources
        self.local = {}
        self.connection = {}
        self.remote = {}  # TODO rename remote to destination?

        # concatenate all CIB repositories
        self.entries = ChainMap(self.remote, self.connection, self.local)

        if cib_dir:
            self.load_cib(cib_dir)

    def __getitem__(self, idx):
        """Return a new PropertyDict containing the properties associated with a CIB index"""
        entry = self.entries[idx]
        properties = PropertyDict()

        if not entry.get('type') == CONNECTION:
            for k, v in entry.items():
                if isinstance(v, NEATProperty):
                    properties.insert(v)

        else:
            # for connection type entries expand the associated local and remote entries
            local_id = entry.get('local')
            remote_id = entry.get('remote')

            new_entry = {}

            # properties are overwritten in the following order: remote>connection>local
            new_entry.update({i.key: i for i in self.entries[local_id].values() if isinstance(i, NEATProperty)})
            new_entry.update({i.key: i for i in self.entries[idx].values() if isinstance(i, NEATProperty)})
            new_entry.update({i.key: i for i in self.entries[remote_id].values() if isinstance(i, NEATProperty)})

            for k, v in new_entry.items():
                properties.insert(v)

        return properties

    def load_json(self, filename):
        """Read JSON file"""

        cib_file = open(filename, 'r')
        try:
            j = json.load(cib_file)
        except json.decoder.JSONDecodeError as e:
            logging.error("Could not parse CIB file " + filename)
            print(e)
            return
        return j

    def load_cib(self, cib_dir='cib/'):
        """Read all CIB source files from directory CIB_DIR"""
        for filename in os.listdir(cib_dir):
            # TODO fix order of loading CIB sources
            if filename.endswith(('.local', '.remote', '.connection')):
                print('loading CIB source %s' % filename)
                p = self.load_json(cib_dir + filename)
                if not p:
                    continue
                p['filename'] = filename
                properties = PropertyDict()
                properties.insert_dict(p.get('properties', {}))
                # TODO convert CIB to PropertyDict
                import code
                code.interact(local=locals())
                # convert JSON properties to NEATProperties
                for key, value in p.pop('informational', {}).items():
                    p[key] = NEATProperty((key, value), precedence=NEATProperty.INFORMATIONAL)
                for key, value in p.pop('requested', {}).items():
                    p[key] = NEATProperty((key, value), precedence=NEATProperty.REQUESTED)
                for key, value in p.pop('immutable', {}).items():
                    p[key] = NEATProperty((key, value), precedence=NEATProperty.IMMUTABLE)

                self.register(p)

    def register(self, cib_source={}):
        """Register loaded CIB sources with CIB repository"""
        # CIB types [local] <<>> [connection] <<>> [remote]
        current_type = cib_source.get("type")
        if current_type not in ['local', 'connection', 'remote']:
            logging.warning("Ignoring invalid type \"" + current_type + "\" for CIB " + cib_source['filename'])
            return
        current_idx = cib_source.get("id")
        # cib_properties = PropertyDict()
        # TODO for now we assume that all CIB properties are informational
        # FIXME
        # cib_properties.update(cib_source, precedence=NEATProperty.INFORMATIONAL)

        # e.g. self.local['d1'] = {...}
        getattr(self, current_type)[current_idx] = cib_source

    def get_connection(self, idx):
        """Return the full connection properties including the properties of the
associated local and remote CIB entries.

        """
        connection = {}
        connection.update(self.connection[idx])
        remote_idx = connection[REMOTE]
        local_idx = connection[LOCAL]
        connection.update(self.local[local_idx])
        connection.update(self.remote[remote_idx])
        return {k: connection[k] for k in connection.keys() - CIB.meta_keys}

    def lookup(self, query, candidate_num=5):
        """CIB lookup logic implementation. Appends a list of connection candidates to the query object. TODO
        """
        candidates = []

        # check connection CIB sources first
        for idx in self.connection.keys():
            matched_properties = self[idx].intersection(query.properties)
            candidate = NEATCandidate(self[idx])
            skip_candidate = False
            for property in matched_properties.values():
                try:
                    candidate.properties.insert(property)
                except NEATPropertyError as e:
                    logging.debug(e)
                    skip_candidate = True
                    break
            if skip_candidate:
                continue
            candidates.append(candidate)

        candidates.sort(key=operator.attrgetter('score'), reverse=True)
        query.candidates = candidates[0:candidate_num]
        # TODO expand lookup to different cib types

        for idx in self.local.keys():
            matched_properties = self[idx].intersection(query.properties)
            candidate = NEATCandidate(self[idx])
            skip_candidate = False
            for property in query.properties.values():
                try:
                    candidate.properties.insert(property)
                except NEATPropertyError as e:
                    logging.debug(e)
                    skip_candidate = True
                    break
            if skip_candidate:
                continue
            candidates.append(candidate)
        candidates.sort(key=operator.attrgetter('score'), reverse=True)
        query.candidates = candidates[0:candidate_num]

    def dump(self):
        keys = list(self.entries.keys())
        keys.sort()
        for k in keys:
            print('%s: %s' % (k, self[k]))

    def __repr__(self):
        return 'CIB<%d>' % (len(self.local) + len(self.connection) + len(self.remote))

    def __str__(self):
        s = ''
        for k, v in self.connection.items():
            if not k == 'type':
                s += str(v[LOCAL]) + ' <-> ' + str(k) + ' <-> ' + str(v[REMOTE]) + '\n'
        return s


if __name__ == "__main__":
    import code

    cib = CIB()
    cib.load_cib()

    print(cib)

    query = NEATRequest({"is_wired_interface": "True"})
    query.properties.insert(NEATProperty(('remote_address', '23:::23:12')))
    query.properties.insert(NEATProperty(('foo', 'bar')))

    code.interact(local=locals())
    # create an example NEAT policy
    p = NEATPolicy()
    p.name = "dynamic"
    p.match.insert(NEATProperty(("is_wired_interface", "True"), 2))
    p.properties.insert(NEATProperty(("MTU", "9600"), 0))
    p.properties.insert(NEATProperty(("TCP_CC", "cubic"), 2))

    print("query: ")
    print(query)

    # lookup CIB
    cib.lookup(query)

    code.interact(local=locals())
