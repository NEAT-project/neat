import bisect
import json
import logging
import os
import shutil

from policy import PropertyArray, PropertyMultiArray, dict_to_properties, ImmutablePropertyError

logging.basicConfig(format='[%(levelname)s]: %(message)s', level=logging.DEBUG)

POLICY_DIR = "pib/examples/"


def load_policy_json(filename):
    """Read and decode a .policy JSON file and return a NEATPolicy object."""
    try:
        policy_file = open(filename, 'r')
        policy_dict = json.load(policy_file)
    except OSError as e:
        logging.error('Policy ' + filename + ' not found.')
        return
    except json.decoder.JSONDecodeError as e:
        logging.error('Error parsing policy file ' + filename)
        print(e)
        return

    p = NEATPolicy(policy_dict)
    return p


class NEATPolicy(object):
    """NEAT policy representation"""

    def __init__(self, policy_dict, name='NA'):
        # set default values
        self.idx = id(self)
        self.name = policy_dict.get('name', name)

        for k, v in policy_dict.items():
            if isinstance(v, str):
                setattr(self, k, v)

        self.priority = int(policy_dict.get('priority', 0))
        self.replace_matched = policy_dict.get('replace_matched', False)

        # parse match fields
        match = policy_dict.get('match', {})
        self.match = PropertyArray()
        self.match.add(*dict_to_properties(match))

        # parse properties
        properties = policy_dict.get('properties', {})
        self.properties = PropertyMultiArray()
        self.properties.add(*dict_to_properties(properties))

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

        ## find intersection
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
        return "%d POLICY %s: %s   ==>   %s" % (self.priority, self.name, self.match, self.properties)

    def __repr__(self):
        return repr({a: getattr(self, a) for a in ['name', 'match', 'properties', 'priority']})


class PIB(list):
    def __init__(self, policy_dir=None, file_extension=('.policy', '.profile')):
        super().__init__()
        self.file_extension = file_extension
        self.policies = self
        self.index = {}

        if policy_dir:
            self.load_policies(policy_dir)

    def load_policies(self, policy_dir=POLICY_DIR):
        """Load all policies in policy directory."""
        for filename in os.listdir(policy_dir):
            if filename.endswith(self.file_extension) and not filename.startswith(('.', '#')):
                print('loading policy %s' % filename)
                p = load_policy_json(os.path.join(policy_dir, filename))
                if p:
                    self.register(p)

    def register(self, policy):
        """Register new policy

        Policies are ordered
        """
        # check for existing policies with identical match properties
        if policy.match in [p.match for p in self.policies]:
            logging.warning("Policy match fields for policy %s already registered. " % (policy.name))
            #return

        # TODO tie breaker using match_len?
        idx = bisect.bisect([p.priority for p in self.policies], policy.priority)
        self.policies.insert(idx, policy)

        # self.policies.sort(key=operator.methodcaller('match_len'))
        self.index[policy.idx] = policy

    def lookup(self, input_properties, apply=True, cand_id=None):
        """
        Look through all installed policies to find the ones which match the properties of the given candidate.
        If apply is True, append the matched policy properties.

        Returns all matched policies.
        """

        assert isinstance(input_properties, PropertyArray)
        if cand_id is None:
            cand_id = ""

        logging.info("matching policies for candidate %s" % cand_id)

        candidates = [input_properties]

        for p in self.policies:
            if p.match_query(input_properties):
                tmp_candidates = []
                policy_info  = str(p.name)
                if hasattr(p, "description"):
                    policy_info += ': %s' % p.description
                logging.info("    " + policy_info)
                if apply:
                    while candidates:
                        candidate = candidates.pop()
                        # if replace_matched was set, remove any occurrence of match properties from the candidate
                        if p.replace_matched:
                            for key in p.match:
                                del candidate[key]
                                logging.debug('    removing property:' + key)

                        for policy_properties in p.properties.expand():
                            try:
                                new_candidate = candidate + policy_properties
                            except ImmutablePropertyError:
                                continue
                            #  TODO copy policies from candidate and policy_properties for debugging
                            #  if hasattr(new_candidate, 'policies'):
                            #      new_candidate.policies.append(p.idx)
                            #  else:
                            #      new_candidate.policies = [p.idx]
                            tmp_candidates.append(new_candidate)
                candidates.extend(tmp_candidates)
        return candidates

    def dump(self):
        ts = shutil.get_terminal_size()
        tcol = ts.columns
        s = "=" * int((tcol - 11) / 2) + " PIB START " + "=" * int((tcol - 11) / 2) + "\n"
        for p in self.policies:
            s += str(p) + '\n'
        s += "=" * int((tcol - 9) / 2) + " PIB END " + "=" * int((tcol - 9) / 2) + "\n"
        print(s)


if __name__ == "__main__":
    pib = PIB('pib/examples/')
    pib.dump()

    import code
    code.interact(local=locals(), banner='PIB loaded:')
