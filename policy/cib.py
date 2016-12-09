import bisect
import copy
import hashlib
import itertools
import json
import logging
import operator
import os
import time
from collections import ChainMap

from pmconst import *
from policy import NEATProperty, PropertyArray, PropertyMultiArray, ImmutablePropertyError, term_separator
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


# TODO rename to CIBNode?
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
        self.expire = source_dict.get('expire', None)
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
            self.properties.append(pa)

        self.uid = source_dict.get('uid')
        if self.uid is None:
            self.uid = self._gen_uid()

    def dict(self):
        d = {}
        for attr in ['uid', 'root', 'link', 'priority', 'filename', 'description', 'expire', ]:
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

    @property
    def expire(self):
        return self._expire

    @expire.setter
    def expire(self, value):
        if value is None:
            self._expire = time.time() + CIB_DEFAULT_TIMEOUT
            return

        value = float(value)

        if value == -1:
            # does not expire
            self._expire = value
        elif time.time() > value:
            raise CIBEntryError('CIB node is expired')
        else:
            self._expire = value

    def _gen_uid(self):
        # FIXME generate persistent UIDs
        d = self.dict()
        for k in ['expire', 'filename']:
            try:
                del d[k]
            except KeyError:
                pass

        for k in ['cib_uids', ]:
            try:
                del d['properties'][k]
            except KeyError:
                pass
        s = json.dumps(d, indent=0, sort_keys=True)
        return hashlib.md5(s.encode('utf-8')).hexdigest()

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
            if match_properties <= entry:
                return True
        return False

    def expand(self):
        for pma in self.properties:
            for p in pma.expand():
                yield p

    def update_links_from_match(self):
        """
        Look at the list elements in self.match and try to match all of its properties to another CIB entry. Generates a
         list containing the UIDs of the matched rows. The list is store in self.links.
        """
        links = set()
        uid_property = {NEATProperty(('uid', self.uid), score=0, precedence=NEATProperty.IMMUTABLE)}
        for match_properties in self.match:
            for uid in self.cib.uid.keys() - self.uid:
                for p in self.cib.uid[uid].expand():
                    # Check if the properties in the match list are a full subset of some CIB properties.
                    # We include our own UID in the property list to enable matching against UIDs.
                    if match_properties <= set(p.values()) | uid_property:
                        links.add(uid)
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
        """Generate CIB rows by expanding all CIBs pointing to current CIB """
        paths = self.resolve_graph()

        # for storing expanded rows
        rows = []

        for path in paths:
            expanded_properties = (self.cib[uid].expand() for uid in path)
            for pas in itertools.product(*expanded_properties):
                chain = ChainMap(*pas)

                # For debugging purposes, add the path list to the chain.
                # Store as string to preserve path order (NEAT properties are not ordered).
                dbg_path = '<<'.join(uid for uid in path)

                # insert at position 0 to override any existing entries
                # chain.maps.insert(0, PropertyArray(NEATProperty(('cib_uids', dbg_path))))

                # convert back to normal PropertyArrays
                row = PropertyArray(*(p for p in chain.values()))
                row.meta['cib_uids'] = dbg_path
                rows.append(row)

        if not apply_extended:
            return rows

        if not self.cib.extenders:
            # no extender CIB sources loaded
            return rows

        # TODO optimize
        extended_rows = rows.copy()
        for entry in rows:
            # TODO take priorities into account
            # iterate extender cib_sources
            for uid, xs in self.cib.extenders.items():
                for pa in xs.expand():
                    if xs.match_entry(entry):
                        entry_copy = copy.deepcopy(entry)
                        chain = ChainMap(pa, entry_copy)
                        new_pa = PropertyArray(*(p for p in chain.values()))
                        try:
                            del new_pa['uid']
                        except KeyError:
                            pass
                        extended_rows.append(new_pa)

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
            deleted_cs = [cs for cs in self.uid.values() if cs.filename == filename]
            # remove corresponding CIBSource object
            for cs in deleted_cs:
                self.uid.pop(uid, None)

        # update links for all registered CIBs
        for cs in self.uid.values():
            cs.update_links_from_match()

        self.gen_graph()
        # self.dump()  # xxx

    def load_cib_file(self, filename):
        cs = load_json(filename)
        if not cs:
            logging.warning("CIB source file %s was invalid" % filename)
            return
        try:
            cib_source = CIBSource(cs)
        except CIBEntryError as e:
            logging.error("Unable to load CIB source %s: %s" % (filename, e))
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
        Import JSON formatted CIB entries into current cib.
        """

        # TODO optimize

        try:
            json_slim = json.loads(slim)
        except json.decoder.JSONDecodeError:
            logging.warning('invalid CIB file format')
            return

        # check if we received multiple objects in a list
        if isinstance(json_slim, list):
            for c in json_slim:
                self.import_json(json.dumps(c))
            return

        # convert to CIB source object to do sanity check
        cs = CIBSource(json_slim)

        if uid is not None:
            cs.uid = uid

        filename = cs.uid
        slim = cs.json()

        if not filename:
            logging.warning("CIB entry has no UID")
            # generate CIB filename
            filename = hashlib.md5(slim.encode('utf-8')).hexdigest()

        filename = '%s.cib' % filename.lower()

        with open(os.path.join(self.cib_dir, '%s' % filename), 'w') as f:
            f.write(slim)
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
                # FIXME better check whether all input properties are included in row - improve matching
                import code
                # code.interact(local=locals(), banner='herexxx')
                # ignore optional properties in input request
                i = PropertyArray(*(p for p in input_properties.values() if p.precedence > NEATProperty.OPTIONAL))
                if len(i & e) != len(i):
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
        print(term_separator("CIB START"))
        # ============================================================================
        for e in self.rows:
            print(str(e) + '\n')
        # ============================================================================
        print(term_separator("CIB END"))

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
