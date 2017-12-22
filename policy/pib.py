import bisect
import hashlib
import json
import logging
import os

import sys
import time

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
        properties = policy_dict.get('properties', [])
        if not isinstance(properties, list):
            # properties should be in a list.
            properties = [properties]
        self.properties = PropertyMultiArray()
        for p in properties:
            if isinstance(p, list):
                self.properties.add([PropertyArray.from_dict(ps) for ps in p])
            else:
                self.properties.add(PropertyArray.from_dict(p))

        # set UID
        self.uid = policy_dict.get('uid')
        if self.uid is None:
            self.uid = self.__gen_uid()
        else:
            self.uid = str(self.uid).lower()

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
        d['properties'] = self.properties.list()

        return d

    def json(self):
        return json.dumps(self.dict(), indent=4, sort_keys=True)

    def match_len(self):
        """Use the number of match elements to sort the entries in the PIB.
        Entries with the smallest number of elements are matched first."""
        return len(self.match)

    def match_query(self, input_properties, strict=False):
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
        return {v.filename: v for v in self.policies}

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
            logging.debug("Policy saved as \"%s\"." % filename)

        # FIXME register
        self.reload_files()

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

    def reload_files(self):
        """
        Reload PIB files
        """
        current_files = set()

        for dir_path, dir_names, filenames in os.walk(self.policy_dir):
            for f in filenames:
                if not f.endswith(self.file_extension) or f.startswith(('.', '#')):
                    continue
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

        # check if a policy with the same UID is already installed and remove old version if so
        if policy.uid in self.index:
            self.unregister(policy.uid)

        # TODO tie breaker using match_len?
        idx = bisect.bisect([p.priority for p in self.policies], policy.priority)
        self.policies.insert(idx, policy)

        # self.policies.sort(key=operator.methodcaller('match_len'))
        self.index[policy.uid] = idx

    def unregister(self, policy_uid):
        """
        Remove policy from in-memory repository. This does not remove the policy from the file system.
        """
        idx = self.index[policy_uid]
        del self.policies[idx]
        del self.index[policy_uid]

    def remove(self, policy_uid):
        self.unregister(policy_uid)

    def lookup(self, input_properties, apply=True, tag=None):
        """
        Look through all installed policies and apply the ones which match against the properties of the given candidate.

        If apply is False, do not append the matched policy properties (dry run).

        Returns all matched policies.
        """

        assert isinstance(input_properties, PropertyArray)
        if tag is None:
            tag = ''

        logging.info("matching policies %s" % tag)
        candidates = [input_properties]
        processed_candidates = []

        # iterate through all policies and apply them to candidate.
        for p in self.policies:
            policy_info = str(p.uid)
            if hasattr(p, "description"):
                policy_info += ' ' + PM.STYLES.DARK_GRAY_START + '(%s)' % p.description + PM.STYLES.FORMAT_END
            updated_candidates = []
            for cand in candidates:
                if p.match_query(cand):
                    logging.info(' ' * 4 + policy_info)
                    if not apply:
                        continue
                    # if replace_matched attribute is true, remove the matched properties from the candidate
                    if p.replace_matched:
                        for key in p.match:
                            del cand[key]
                    for policy_properties in p.properties.expand():
                        try:
                            updated_candidate = cand + policy_properties
                            updated_candidates.append(updated_candidate)
                        except ImmutablePropertyError as e:
                            logging.info(
                                ' ' * 4 + policy_info + PM.STYLES.BOLD_START + ' *CANDIDATE REJECTED*' + PM.STYLES.FORMAT_END + ' (%s)' % str(e))
                            continue
                else:
                    updated_candidates.append(cand)
            candidates = updated_candidates
            # TODO copy policies from candidate and policy_properties for debugging
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
