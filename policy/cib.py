import bisect
import copy
import hashlib
import itertools
import json
import operator
import time
from collections import ChainMap

import pmdefaults as PM
from pmdefaults import *
from policy import NEATProperty, PropertyArray, PropertyMultiArray, ImmutablePropertyError, term_separator

CIB_EXPIRED = 2


class CIBEntryError(Exception):
    pass


def load_json(filename):
    """
    Read CIB node from JSON file
    """

    cib_file = open(filename, 'r')
    try:
        j = json.load(cib_file)
    except json.decoder.JSONDecodeError as e:
        logging.error("Could not parse CIB file " + filename)
        print(e)
        return
    return j


class CIBNode(object):
    cib = None

    def __init__(self, node_dict=None):

        if node_dict is None:
            node_dict = dict()

        if not isinstance(node_dict, dict):
            raise CIBEntryError("invalid CIB object")

        self.root = node_dict.get('root', False)
        # otherwise chain matched CIBs
        self.link = node_dict.get('link', False)
        self.priority = node_dict.get('priority', 0)
        # TTL for the CIB node: the node is considered invalid after the time specified
        self.expire = node_dict.get('expire', None) or node_dict.get('expires', None)  # FIXME expires is deprecated
        self.filename = node_dict.get('filename', None)
        self.description = node_dict.get('description', '')

        # convert to PropertyMultiArray with NEATProperties
        properties = node_dict.get('properties', [])

        if not isinstance(properties, list):
            # properties should be in a list. The list elements are expanded when generating the CIB rows.
            properties = [properties]

        self.properties = PropertyMultiArray()
        for p in properties:
            if isinstance(p, list):
                self.properties.add([PropertyArray.from_dict(ps) for ps in p])
            else:
                self.properties.add(PropertyArray.from_dict(p))

        self.match = []
        # FIXME better error handling if match undefined
        for l in node_dict.get('match', []):
            # convert to NEATProperties
            self.match.append(PropertyArray.from_dict(l))

        self.linked = set()
        if self.link and not self.match:
            logging.warning('link attribute set but no match field!')

        self.uid = node_dict.get('uid')
        if self.uid is None:
            self.uid = self._gen_uid()

    def dict(self):
        d = {}
        for attr in ['uid', 'root', 'link', 'priority', 'filename', 'description', 'expire', ]:
            try:
                d[attr] = getattr(self, attr)
            except AttributeError:
                logging.debug("CIB node doesn't contain attribute %s" % attr)

        if self.match:
            d['match'] = []
            for m in self.match:
                d['match'].append(m.dict())

        d['properties'] = self.properties.list()
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
            raise CIBEntryError('ignoring expired CIB node', CIB_EXPIRED)
        else:
            self._expire = value

    def _gen_uid(self):
        # FIXME generate persistent UIDs
        d = self.dict()
        for k in ['expire', 'filename', 'uid', ]:
            try:
                del d[k]
            except KeyError:
                pass

        s = json.dumps(d, indent=0, sort_keys=True)
        return hashlib.md5(s.encode('utf-8')).hexdigest()

    def json(self, indent=4):
        return json.dumps(self.dict(), indent=indent, sort_keys=True)

    def resolve_paths(self, path=None):
        """recursively find all paths from this CIBNode to all other matched CIBnodes in the CIB graph"""
        if path is None:
            path = []
        # insert own index based on CIB node priority to resolve overlapping properties later
        # FIXME priorities no longer work
        pos = bisect.bisect([self.cib[uid].priority for uid in path], self.priority)
        path.insert(pos, self.uid)

        # no more links to check
        if not (self.linked - set(path)):
            return [path]

        new_paths = []
        for uid in self.linked:
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
        for p in self.properties.expand():
            yield p

    def update_links_from_match(self):
        """
        Look at the list elements in self.match and try to match all of its properties to another CIB entry. Generates a
         list containing the UIDs of the matched rows. The list is stored in self.linked.
        """

        for match_properties in self.match:
            for node in self.cib.nodes.values():
                if node.uid == self.uid: continue  # ??
                for p in node.expand():
                    # Check if the properties in the match list are a full subset of some CIB properties.
                    # Also include the CIB uid as a property while matching
                    if match_properties <= set(p.values()) | {NEATProperty(('uid', node.uid))}:
                        self.linked.add(node.uid)

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
            paths = self.cib.nodes[u].resolve_graph(path.copy())
            new_paths.extend(paths)
        return new_paths

    def resolve_links(self, path=None):
        """find paths from current CIB to all linked CIBS """
        if path is None:
            path = []
        # insert own index based on CIB node priority to resolve overlapping properties later
        pos = bisect.bisect([self.cib[uid].priority for uid in path], self.priority)
        path.insert(pos, self.uid)

        # no more links to check
        if not (self.linked - set(path)):
            return [path]

        new_paths = []
        for uid in self.linked:
            if uid in path:
                continue
            new_paths.extend(self.cib[uid].resolve_links(path.copy()))
        return new_paths

    def expand_rows(self, apply_extended=True):
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
            # no extender CIB nodes loaded
            return rows

        # TODO optimize
        extended_rows = rows.copy()
        for entry in rows:
            # TODO take priorities into account
            # iterate extender cib_nodes
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
        s = str(self.properties)
        if self.linked:
            s += " linked@%s" % self.linked
        return s


class CIB(object):
    """
    Internal representation of the CIB for testing

    """

    cib_dir = PM.CIB_DIR
    CIB_EXTENSIONS = ('.cib', '.local', '.connection', '.remote', '.slim')

    def __init__(self, cib_dir=None):
        # dictionary containing all loaded CIB nodes, keyed by their uid
        self.nodes = {}
        # track CIB files
        self.files = dict()

        CIBNode.cib = self

        self.graph = {}

        if cib_dir:
            self.cib_dir = cib_dir
            self.reload_files()

    def __getitem__(self, uid):
        return self.nodes[uid]

    def items(self):
        return self.nodes.items()

    def keys(self):
        return self.nodes.keys()

    def values(self):
        return self.nodes.values()

    @property
    def roots(self):
        return {k: v for k, v in self.nodes.items() if v.root is True}

    @property
    def extenders(self):
        return {k: v for k, v in self.nodes.items() if not v.link}

    @property
    def rows(self):
        """
        Returns a generator containing all expanded root CIB nodes
        """

        for uid, r in self.roots.items():
            # expand all cib nodes
            for entry in r.expand_rows():
                entry.cib_node = uid
                yield entry

    def reload_files(self, cib_dir=None):
        """
        Reload CIB files when a change is detected on disk
        """
        if not cib_dir:
            cib_dir = self.cib_dir

        full_names = set()

        logging.info("checking for CIB updates...")

        if not os.path.exists(cib_dir):
            sys.exit('CIB directory %s does not exist' % cib_dir)

        for dirpath, dirnames, filenames in os.walk(cib_dir):
            for filename in filenames:
                if not filename.endswith(CIB.CIB_EXTENSIONS) or filename.startswith(('.', '#')):
                    continue
                full_name = os.path.join(dirpath, filename)
                stat = os.stat(full_name)
                full_names.add(full_name)
                if full_name in self.files:
                    if self.files[full_name] != stat.st_mtime_ns:
                        logging.info("CIB node %s has changed", full_name)
                        self.files[full_name] = stat.st_mtime_ns
                        self.load_cib_file(full_name)
                else:
                    logging.info("Loading new CIB node %s.", full_name)
                    self.files[full_name] = stat.st_mtime_ns
                    self.load_cib_file(full_name)

        removed_files = self.files.keys() - full_names
        for filename in removed_files:
            logging.info("CIB node %s has been removed", filename)
            del self.files[filename]
            deleted_cs = [cs for cs in self.nodes.values() if cs.filename == filename]
            # remove corresponding CIBNode object
            for cs in deleted_cs:
                self.nodes.pop(uid, None)

        self.update_graph()

    def load_cib_file(self, filename):
        cs = load_json(filename)
        if not cs:
            logging.warning("CIB node file %s was invalid" % filename)
            return
        try:
            cib_node = CIBNode(cs)
        except CIBEntryError as e:
            if CIB_EXPIRED in e.args:
                logging.debug("Ignoring CIB node %s: %s" % (filename, e.args[0]))
                return
            logging.error("Unable to load CIB node %s: %s" % (filename, e.args[0]))
            return

        cib_node.filename = filename
        self.register(cib_node)

    def update_graph(self):
        # FIXME this tree should be rebuilt dynamically

        # update links for all registered CIBs
        for cs in self.nodes.values():
            cs.update_links_from_match()
        # FIXME check for invalid pointers

        self.graph = {}
        for i in self.nodes.values():
            if not i.link:
                continue
            for r in i.linked:
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

        # convert to CIB node object to do sanity check
        try:
            cs = CIBNode(json_slim)
        except CIBEntryError as e:
            print(e)
            return

        # no not import cache nodes if disabled
        if not PM.CIB_CACHE and any(['__cached' in p for p in cs.properties.expand()]):
            logging.debug('Ignoring cache CIB node')
            return

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
            logging.debug("CIB entry saved as \"%s\"." % filename)

        self.reload_files()

    def register(self, cib_node):
        if cib_node in self.nodes:
            logging.debug("overwriting existing CIB with uid %s" % cib_node.uid)
        self.nodes[cib_node.uid] = cib_node

    def unregister(self, cib_uid):
        del self.nodes[cib_uid]
        self.update_graph()

    def remove(self, cib_uid):
        self.unregister(cib_uid)

    def lookup(self, input_properties, candidate_num=5):
        """CIB lookup logic implementation

        Return CIB rows that include *all* required properties from the request PropertyArray
        """
        assert isinstance(input_properties, PropertyArray)
        candidates = [input_properties]
        for e in self.rows:
            try:
                # FIXME better check whether all input properties are included in row - improve matching
                # ignore optional properties in input request
                required_pa = PropertyArray(
                    *(p for p in input_properties.values() if p.precedence == NEATProperty.IMMUTABLE))
                if len(required_pa & e) != len(required_pa):
                    continue
            except ImmutablePropertyError:
                continue
            try:
                candidate = e + input_properties
                candidate.cib_node = e.cib_node
                candidates.append(candidate)
            except ImmutablePropertyError:
                pass

        return sorted(candidates, key=operator.attrgetter('score'), reverse=True)[:candidate_num]

    def dump(self, show_all=False):
        print(term_separator("CIB START"))
        # ============================================================================
        for i, e in enumerate(self.rows):
            print("%3i. %s" % (i, str(e)))
        # ============================================================================
        print(term_separator("CIB END"))

    def __repr__(self):
        return 'CIB<%d>' % (len(self.nodes))


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
        # print(i, i.cib_node, i.score)
