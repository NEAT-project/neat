import bisect
import hashlib
import json
import logging
import os
import time

import sys

import pmdefaults as PM
from policy import PropertyArray, PropertyMultiArray, dict_to_properties, ImmutablePropertyError, term_separator

PIB_EXTENSIONS = ('.policy', '.profile', '.pib')


class NEATPIBError(Exception):
    pass


def load_policy_json(filename):
    """Read and decode a .policy JSON file and return a NEATPolicy object."""
    try:
        policy_file = open(filename, 'r')
        policy_dict = json.load(policy_file)
    except OSError as e:
        logging.error('Policy ' + filename + ' not found.')
        raise NEATPIBError(e)
    except json.decoder.JSONDecodeError as e:
        logging.error('Error parsing policy file ' + filename)
        print(e)
        raise NEATPIBError(e)

    p = NEATPolicy(policy_dict)
    return p


class NEATPolicy(object):
    """NEAT policy representation"""

    def __init__(self, policy_dict=None, uid=None):
        # set default values

        if policy_dict is None:
            policy_dict = dict()

        if uid is not None:
            policy_dict['uid'] = uid

        # TODO do we need to handle unknown attributes?
        for k, v in policy_dict.items():
            if isinstance(v, str):
                setattr(self, k, v)

        self.priority = int(policy_dict.get('priority', 0))
        self.replace_matched = policy_dict.get('replace_matched', False)

        self.filename = None
        self.time = time.time()

        # parse match fields
        match = policy_dict.get('match', {})
        self.match = PropertyArray()
        self.match.add(*dict_to_properties(match))

        # parse augment properties
        properties = policy_dict.get('properties', {})
        self.properties = PropertyMultiArray()
        self.properties.add(*dict_to_properties(properties))

        # set UID
        self.uid = policy_dict.get('uid')
        if self.uid is None:
            self.uid = self.__gen_uid()
        else:
            self.uid = str(self.uid).lower()

        # deprecated
        self.name = policy_dict.get('name', self.uid)

    def __gen_uid(self):
        # TODO make UID immutable?
        s = str(id(self))
        return hashlib.md5(s.encode('utf-8')).hexdigest()

    def dict(self):
        d = {}
        for attr in ['uid', 'priority', 'replace_matched', 'filename', 'time']:
            try:
                d[attr] = getattr(self, attr)
            except AttributeError:
                logging.warning("Policy doesn't contain attribute %s" % attr)

        d['match'] = self.match.dict()
        d['properties'] = self.properties.dict()

        return d

    def json(self):
        return json.dumps(self.dict(), indent=4, sort_keys=True)

    def match_len(self):
        """Use the number of match elements to sort the entries in the PIB.
        Entries with the smallest number of elements are matched first."""
        return len(self.match)

    def match_query(self, input_properties, strict=True):
        """Check if the match properties are completely covered by the properties of a query.

        If strict flag is set match only properties with precedences that are higher or equal to the precedence
        of the corresponding match property.
        """

        # always return True if the match field is empty (wildcard)
        if not self.match:
            return True

        # TODO check
        # find full overlap?
        if not self.match.items() <= input_properties.items():
            return

        # find intersection
        matching_props = self.match.items() & input_properties.items()

        if strict:
            # ignore properties with a lower precedence than the associated match property
            return bool({k for k, v in matching_props if input_properties[k].precedence >= self.match[k].precedence})
        else:
            return bool(matching_props)

    def apply(self, properties: PropertyArray):
        """Apply policy properties to a set of candidate properties."""
        for p in self.properties.values():
            logging.info("applying property %s" % p)
            properties.add(*p)

    def __str__(self):
        return '%3s. %-8s %s  %s  %s' % (self.priority, self.uid, self.match, PM.CHARS.RIGHT_ARROW, self.properties)

    def __repr__(self):
        return repr({a: getattr(self, a) for a in ['uid', 'match', 'properties', 'priority']})


class PIB(list):
    def __init__(self, policy_dir, file_extension=('.policy', '.profile'), policy_type='policy'):
        super().__init__()
        self.policies = self
        self.index = {}

        self.file_extension = file_extension
        # track PIB files

        self.policy_type = policy_type
        self.policy_dir = policy_dir
        self.load_policies(self.policy_dir)

    @property
    def files(self):
        return {v.filename: v for uid, v in self.index.items()}

    def load_policies(self, policy_dir=None):
        """Load all policies in policy directory."""

        if not policy_dir:
            policy_dir = self.policy_dir

        if not os.path.exists(policy_dir):
            sys.exit('PIB directory %s does not exist' % policy_dir)

        for filename in os.listdir(policy_dir):
            if filename.endswith(self.file_extension) and not filename.startswith(('.', '#')):
                self.load_policy(os.path.join(policy_dir, filename))

    def import_json(self, slim, uid=None):
        """
        Import a JSON formatted PIB entry into current pib.
        """

        try:
            pib_entry = json.loads(slim)
        except json.decoder.JSONDecodeError:
            logging.warning('invalid PIB file format')
            return

        # check if we received multiple objects in a list
        if isinstance(pib_entry, list):
            for p in pib_entry:
                self.import_json(json.dumps(p))
            return

        policy = NEATPolicy(pib_entry)
        if uid is not None:
            policy.uid = uid

        filename = policy.uid

        # if not filename:
        #    # generate hash policy filename
        #   filename = hashlib.md5('json_slim'.encode('utf-8')).hexdigest()

        filename = '%s.policy' % filename.lower()
        policy.filename = filename

        filename = os.path.join(self.policy_dir, filename)

        with open(filename, 'w') as f:
            f.write(policy.json())

        logging.info("Policy saved as \"%s\"." % filename)

        # FIXME register
        self.reload()

    def load_policy(self, filename):
        """Load policy.
        """
        if not filename.endswith(self.file_extension) and filename.startswith(('.', '#')):
            return
        stat = os.stat(filename)

        t = stat.st_mtime_ns
        if filename not in self.files or self.files[filename].timestamp != t:
            logging.info("Loading policy %s...", filename)
            try:
                p = load_policy_json(filename)
            except NEATPIBError as e:
                logging.error("Unable not load policy %s" % filename)
                return

            # update filename and timestamp
            p.filename = filename
            p.timestamp = t
            if p:
                self.register(p)
        else:
            pass
            # logging.debug("Policy %s is up-to-date", filename)

    def reload(self):
        """
        Reload PIB files
        """
        current_files = set()

        for dir_path, dir_names, filenames in os.walk(self.policy_dir):
            for f in filenames:
                full_name = os.path.join(dir_path, f)
                current_files.add(full_name)
                self.load_policy(full_name)

        # check if any files were deleted
        deleted_files = self.files.keys() - current_files

        for f in deleted_files:
            logging.info("Policy file %s has been deleted", f)
            # unregister policy
            self.unregister(self.files[f].uid)

    def register(self, policy):
        """Register new policy

        Policies are ordered by their priority attribute
        """
        # check for existing policies with identical match properties
        if policy.match in [p.match for p in self.policies]:
            # logging.debug("Policy match fields for policy %s already registered. " % (policy.uid))
            pass

        # TODO tie breaker using match_len?
        uid = bisect.bisect([p.priority for p in self.policies], policy.priority)
        self.policies.insert(uid, policy)

        # self.policies.sort(key=operator.methodcaller('match_len'))
        self.index[policy.uid] = policy

    def unregister(self, policy_uid):
        del self.index[policy_uid]

    def lookup(self, input_properties, apply=True, tag=None):
        """
        Look through all installed policies to find the ones which match the properties of the given candidate.
        If apply is True, append the matched policy properties.

        Returns all matched policies.
        """

        assert isinstance(input_properties, PropertyArray)
        if tag is None:
            tag = ''

        logging.info("matching policies %s" % tag)
        candidates = [input_properties]

        for p in self.policies:
            if p.match_query(input_properties):
                tmp_candidates = []

                policy_info = str(p.uid)
                if hasattr(p, "description"):
                    policy_info += ' (%s)' % p.description

                if apply:
                    while candidates:
                        candidate = candidates.pop()
                        # if replace_matched is true, remove all matched properties from the candidate
                        if p.replace_matched:
                            for key in p.match:
                                del candidate[key]

                        for policy_properties in p.properties.expand():
                            try:
                                new_candidate = candidate + policy_properties
                            except ImmutablePropertyError:
                                logging.info(
                                    ' ' * 4 + policy_info + PM.STYLES.BOLD_START + ' *REJECTED*' + PM.STYLES.FORMAT_END)
                                return []
                            # TODO copy policies from candidate and policy_properties for debugging
                            #  if hasattr(new_candidate, 'policies'):
                            #      new_candidate.policies.append(p.uid)
                            #  else:
                            #      new_candidate.policies = [p.uid]
                            tmp_candidates.append(new_candidate)
                candidates.extend(tmp_candidates)

                logging.info(' ' * 4 + policy_info)
        return candidates

    def dump(self):
        print(term_separator("PIB START"))
        for p in self.policies:
            print(str(p))
        print(term_separator("PIB END"))


if __name__ == "__main__":
    pib = PIB('pib/examples/')
    pib.dump()

    import code

    code.interact(local=locals(), banner='PIB loaded:')
