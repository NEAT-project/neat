import bisect
import copy
import hashlib
import itertools
import json
import logging
import operator
import os
import shutil
from collections import ChainMap

from policy import NEATProperty, PropertyArray, PropertyMultiArray, ImmutablePropertyError
from policy import dict_to_properties

logging.basicConfig(format='[%(levelname)s]: %(message)s', level=logging.DEBUG)


class CIBEntryError(Exception):
    pass


def load_json(filename):
    """
    Read CIB source from JSON file
    """

    cib_file = open(filename, 'r')
    try:
        j = json.load(cib_file)
    except json.decoder.JSONDecodeError as e:
        logging.error("Could not parse CIB file " + filename)
        print(e)
        return
    return j


class CIBSource(object):
    cib = None

    def __init__(self, source_dict):

        if not isinstance(source_dict, dict):
            raise CIBEntryError("received invalid CIB object")

        self.root = source_dict.get('root', False)
        # otherwise chain matched CIBs
        self.link = source_dict.get('link', False)
        if self.root and not self.link:
            # logging.warning("[%s] root: true implies link: true." % self.uid)
            self.link = True
        self.priority = source_dict.get('priority', 0)
        self.filename = source_dict.get('filename', None)
        self.description = source_dict.get('description', '')

        # convert to PropertyMultiArray with NEATProperties
        properties = source_dict.get('properties')
        if properties is None:
            raise CIBEntryError("CIB entry has no 'property' attribute")
        if not isinstance(properties, list):
            # properties should be in a list [NEW STYLE]: FIXME explain why
            properties = [properties]

        self.links = set()
        self.match = []
        # FIXME better error handling if match undefined
        for l in source_dict.get('match', []):
            # convert to NEATProperties
            self.match.append(PropertyArray(*dict_to_properties(l)))

        self.properties = []
        for p in properties:
            pa = PropertyMultiArray(*dict_to_properties(p))
            # include UID as a NEATProperty
            # pa.add(NEATProperty(('uid', self.uid), score=0, precedence=NEATProperty.IMMUTABLE))
            self.properties.append(pa)

        # FIXME generate persistent UIDs

        self.uid = source_dict.get('uid')
        if self.uid is None:
            s = self.json(indent=0)
            self.uid = hashlib.md5(s.encode('utf-8')).hexdigest()

        for p in self.properties:
            # include UID as a NEATProperty
            p.add(NEATProperty(('uid', self.uid), score=0, precedence=NEATProperty.IMMUTABLE))

    def dict(self):
        d = {}
        for attr in ['uid', 'root', 'link', 'priority', 'filename', 'description', ]:

            try:
                d[attr] = getattr(self, attr)
            except AttributeError:
                logging.debug("CIB source doesn't contain attribute %s" % attr)

        d['match'] = []
        for m in self.match:
            d['match'].append(m.dict())

        if len(self.properties) == 1:
            d['properties'] = self.properties[0].dict()
        else:
            d['properties'] = []
            for p in self.properties:
                d['properties'].append(p.dict())

        return d

    def json(self, indent=4):
        return json.dumps(self.dict(), indent=indent, sort_keys=True)

    def resolve_paths(self, path=None):
        """recursively find all paths from this CIBSource to all other matched CIBSources in the CIB graph"""
        if path is None:
            path = []
        # insert own index based on CIB source priority to resolve overlapping properties later
        # FIXME priorities no longer work
        pos = bisect.bisect([self.cib[uid].priority for uid in path], self.priority)
        path.insert(pos, self.uid)

        # no more links to check
        if not (self.links - set(path)):
            return [path]

        new_paths = []
        for uid in self.links:
            if uid in path:
                continue
            new_paths.extend(self.cib[uid].resolve_links(path.copy()))
        return new_paths

    def match_entry(self, entry):
        for match_properties in self.match:
            if set(match_properties.values()) <= set(entry.values()):
                return True
        return False

    def expand(self):
        for pma in self.properties:
            for p in pma.expand():
                yield p

    def update_links_from_match(self):
        """
        Look at the list elements in self.match and try to match all of its properties to another CIB entry. Return a list
         containing the uids of the matched rows.
        """
        links = set()
        for match_properties in self.match:
            for i in self.cib.uid.keys() - self.uid:
                for p in self.cib.uid[i].expand():
                    # check if the properties in the match list are a full subset of some CIB properties
                    if set(match_properties.values()) <= set(p.values()):
                        # logging.debug("%s is in %s uid:%s " % (match_properties, p, self.cib.uid[i].uid))
                        links.add(self.cib.uid[i].uid)
        self.links = links

    def resolve_graph(self, path=None):
        """new try """
        if path is None:
            path = []

        path.append(self.uid)

        remaining = set(self.cib.graph.get(self.uid, [])) - set(path)
        if len(remaining) == 0:
            return [path]

        new_paths = []
        for u in remaining:
            paths = self.cib.uid[u].resolve_graph(path.copy())
            new_paths.extend(paths)
        return new_paths

    def resolve_links(self, path=None):
        """find paths from current CIB to all linked CIBS """
        if path is None:
            path = []
        # insert own index based on CIB source priority to resolve overlapping properties later
        pos = bisect.bisect([self.cib[uid].priority for uid in path], self.priority)
        path.insert(pos, self.uid)

        # no more links to check
        if not (self.links - set(path)):
            return [path]

        new_paths = []
        for uid in self.links:
            if uid in path:
                continue
            new_paths.extend(self.cib[uid].resolve_links(path.copy()))
        return new_paths

    def gen_rows(self, apply_extended=True):
        """Generate rows by expanding all CIBs pointing to current CIB """
        paths = self.resolve_graph()

        # for storing expanded rows
        rows = []

        for path in paths:
            expanded_properties = (self.cib[uid].expand() for uid in path)
            for pas in itertools.product(*expanded_properties):
                chain = ChainMap(*pas)
                # get list of UIDs of all CIBs in chain and add the in first position of the chain
                uid_list = [p['uid'].value for p in pas]

                chain.maps.insert(0, PropertyArray(NEATProperty(('uid', uid_list))))

                # convert back to normal PropertyArrays
                rows.append(PropertyArray(*(c for c in chain.values())))

        if not apply_extended:
            return rows

        if not self.cib.extenders:
            return rows  # TODO optimize

        extended_rows = rows.copy()
        for entry in rows:
            # TODO take priorities into account
            # iterate extender cib_sources
            for xcs in self.cib.extenders.values():
                for pa in xcs.expand():
                    if xcs.match_entry(entry):
                        entry_copy = copy.deepcopy(entry)
                        chain = ChainMap(pa, entry_copy)
                        new_pa = PropertyArray(*(c for c in chain.values()))
                        try:
                            del new_pa['uid']
                        except KeyError:
                            pass
                        extended_rows.append(new_pa)
                        #                    else:
                        #                        print('noo')

        return extended_rows

    def __repr__(self):
        return "%s @links %s" % (self.properties, self.links)


class CIB(object):
    """
    Internal representation of the CIB for testing

    """

    cib_dir = './cib/example/'
    CIB_EXTENSIONS = ('.cib', '.local', '.connection', '.remote', '.slim')

    def __init__(self, cib_dir=None):
        self.uid = {}
        # track CIB files
        self.files = dict()

        CIBSource.cib = self

        self.graph = {}

        if cib_dir:
            self.cib_dir = cib_dir
            self.reload_files()

    def __getitem__(self, uid):
        return self.uid[uid]

    def items(self):
        return self.uid.items()

    @property
    def roots(self):
        return {k: v for k, v in self.uid.items() if v.root is True}

    @property
    def extenders(self):
        return {k: v for k, v in self.uid.items() if not v.link}

    @property
    def rows(self):
        """
        Returns a generator containing all expanded root CIB sources
        """

        for uid, r in self.roots.items():
            # expand all cib sources
            for entry in r.gen_rows():
                entry.cib_source = uid
                yield entry

    def reload_files(self, cib_dir=None):
        """
        Reload CIB files when a change is detected on disk
        """
        cib_dir = self.cib_dir if not cib_dir else cib_dir
        full_names = set()

        logging.info("checking for CIB updates...")

        for dirpath, dirnames, filenames in os.walk(cib_dir):
            for filename in filenames:
                if not filename.endswith(CIB.CIB_EXTENSIONS) or filename.startswith(('.', '#')):
                    continue
                full_name = os.path.join(dirpath, filename)
                stat = os.stat(full_name)
                full_names.add(full_name)
                if full_name in self.files:
                    if self.files[full_name] != stat.st_mtime_ns:
                        logging.info("CIB source %s has changed", full_name)
                        self.files[full_name] = stat.st_mtime_ns
                else:
                    logging.info("new CIB source %s. loading...", full_name)
                    self.files[full_name] = stat.st_mtime_ns
                    self.load_cib_file(full_name)

        removed_files = self.files.keys() - full_names
        for filename in removed_files:
            logging.info("CIB source %s has been removed", filename)
            del self.files[filename]
            deleted_cs = [cs for cs in cib.uid.values() if cs.filename == filename]
            # remove corresponding CIBSource object
            for cs in deleted_cs:
                self.uid.pop(uid, None)

        # update links for all registered CIBs
        for cs in self.uid.values():
            cs.update_links_from_match()

        self.gen_graph()
        self.dump()  # xxx

    def load_cib_file(self, filename):
        cs = load_json(filename)
        if not cs:
            logging.warning("CIB source file %s was invalid" % filename)
            return
        try:
            cib_source = CIBSource(cs)
        except CIBEntryError as e:
            logging.error("Unable to load CIB source %s" % filename)
            return

        cib_source.filename = filename
        self.register(cib_source)

    def gen_graph(self):
        for i in self.uid.values():
            if not i.link:
                continue
            for r in i.links:
                if r not in self.graph:
                    self.graph[r] = []
                if i.uid not in self.graph[r]:
                    self.graph[r].append(i.uid)

    def import_json(self, slim, uid=None):
        """
        Import JSON formatted CIB entries into current cib. Multiple entries can be concatenated in a JSON array
        """

        # TODO optimize

        try:
            json_slim = json.loads(slim)
        except json.decoder.JSONDecodeError:
            logging.warning('invalid CIB file format')
            return

        # make sure we always get CIB entries as a list
        if not isinstance(json_slim, list):
            json_slim = [json_slim]

        for cib_entry in json_slim:

            cs = CIBSource(cib_entry)

            filename = cs.uid
            slim = cs.json()

            if not filename:
                logging.warning("CIB entry has no UID")
                # generate CIB filename
                filename = hashlib.md5(slim.encode('utf-8')).hexdigest()

            filename = filename.lower() + '.slim'

            f = open(os.path.join(self.cib_dir, '%s' % filename), 'w')
            f.write(slim)
            f.close()
            logging.info("CIB entry saved as \"%s\"." % filename)

        self.reload_files()

    def register(self, cib_source):
        if cib_source in self.uid:
            logging.debug("overwriting existing CIB with uid %s" % cib_source.uid)
        self.uid[cib_source.uid] = cib_source

    def lookup(self, input_properties, candidate_num=5):
        """
        CIB lookup logic implementation. Appends a list of connection candidates to the query object. TODO

        """
        assert isinstance(input_properties, PropertyArray)
        candidates = [input_properties]
        for e in self.rows:
            try:
                # FIXME better check whether all input properties are included in row

                if len(input_properties & e) != len(input_properties):
                    continue

            except ImmutablePropertyError:
                continue

            try:
                candidate = e + input_properties
                candidate.cib_source = e.cib_source
                candidates.append(candidate)
            except ImmutablePropertyError:
                pass

        return sorted(candidates, key=operator.attrgetter('score'), reverse=True)[:candidate_num]

    def dump(self, show_all=False):
        ts = shutil.get_terminal_size()
        tcol = ts.columns

        print("=" * int((tcol - 11) / 2) + " CIB START " + "=" * int((tcol - 11) / 2))
        # ============================================================================
        for e in self.rows:
            print(str(e) + '\n')
        # ============================================================================
        print("=" * int((tcol - 9) / 2) + " CIB END " + "=" * int((tcol - 9) / 2))

    def __repr__(self):
        return 'CIB<%d>' % (len(self.uid))


if __name__ == "__main__":
    cib = CIB('./cib/example/')
    b = cib['B']
    c = cib['C']

    cib.dump()
    import code

    code.interact(local=locals(), banner='CIB')

    for uid in cib.roots:
        z = cib[uid].resolve_links([])
        print(z)

    query = PropertyArray()
    test_request_str = '{"MTU": {"value": [1500, Infinity]}, "low_latency": {"precedence": 2, "value": true}, "remote_ip": {"precedence": 2, "value": "10:54:1.23"}, "transport": {"value": "TCP"}}'
    test = json.loads(test_request_str)
    for k, v in test.items():
        query.add(NEATProperty((k, v['value']), precedence=v.get('precedence', 1)))

    candidates = cib.lookup(query)
    for i in candidates:
        print(i)
        # print(i, i.cib_source, i.score)
