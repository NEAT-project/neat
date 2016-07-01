import json
import logging
import operator
import os
import unittest
import copy
import numbers
import math

logging.basicConfig(format='[%(levelname)s]: %(message)s', level=logging.DEBUG)

POLICY_DIR = "pib/examples/"


class NEATPropertyError(Exception):
    pass


def numeric(value):
    try:
        if isinstance(value, tuple):
            return tuple(float(i) for i in value)
        else:
            return float(value)
    except ValueError:
        return value


class NEATProperty(object):
    """Properties are (key,value) tuples"""

    IMMUTABLE = 2
    REQUESTED = 1
    INFORMATIONAL = 0

    def __init__(self, prop, precedence=REQUESTED, score=float('NaN')):
        self.key = prop[0]
        self._value = prop[1]
        if isinstance(self.value, (tuple, list)):
            self.value = tuple((float(i) for i in self.value))
            if self.value[0] > self.value[1]:
                raise IndexError("Invalid property range")
        self.precedence = precedence

        # a score value of NaN indicates that the property has not been evaluated
        self.score = score
        # TODO experimental meta data
        # specify relationship type between key and value, e.g., using some comparison operator
        self.relation = '=='  # e.g., 'lt', 'gt', 'ge', '==', 'range', ??
        # mark if property has been updated during a lookup
        self.evaluated = False
        # attach more weight to property score
        self.weight = 1.0

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        old_value = self._value
        self._value = value

        if isinstance(old_value, (tuple, numbers.Number)) and isinstance(old_value, (tuple, numbers.Number)):
            # FIXME ensure that tuple values are numeric
            new_value = self._range_overlap(old_value)
            if new_value:
                self._value = new_value

    @property
    def required(self):
        return self.precedence == NEATProperty.IMMUTABLE

    @property
    def requested(self):
        return self.precedence == NEATProperty.REQUESTED

    @property
    def informational(self):
        return self.precedence == NEATProperty.INFORMATIONAL

    @property
    def property(self):
        return self.key, self.value

    def items(self):
        return self.property

    def dict(self, with_score=True):
        """Return a dict for JSON export"""
        json_dict = {self.key: dict(value=self.value, precedence=self.precedence, score=self.score)}
        return json_dict

    def __iter__(self):
        for p in self.property:
            yield p

    def __eq__(self, other):
        """Return true if a single value is in range, or if two ranges have an overlapping region."""
        assert isinstance(other, NEATProperty)

        if not isinstance(other.value, tuple) and not isinstance(self.value, tuple):
            if (self.key, self.value) == (other.key, other.value):
                return self.value

        if not (self.key == other.key):
            logging.debug("Property key mismatch")
            return False

        return self._range_overlap(other.value)

    def __hash__(self):
        # define hash for set comparisons
        return hash(self.key)

    def _range_overlap(self, other_range):
        self_range = self.value

        if isinstance(self.value, tuple):
            if not all(isinstance(i, numbers.Number) for i in self.value):
                raise ValueError("ranges values %s are not numeric" % self.value)
        else:
            if not isinstance(self.value, numbers.Number):
                raise ValueError("value %s is not numeric" % self.value)

        # create a tuple if one of the ranges is a single numerical value
        if isinstance(other_range, numbers.Number):
            other_range = other_range, other_range
        if isinstance(self_range, numbers.Number):
            self_range = self_range, self_range

        # check if ranges have an overlapping region
        overlap = other_range[0] <= self_range[1] and other_range[1] >= self_range[0]

        if not overlap:
            return False
        else:
            # return actual range
            overlap_range = max(other_range[0], self_range[0]), min(other_range[1], self_range[1])
            if overlap_range[0] == overlap_range[1]:
                return overlap_range[0]
            else:
                return overlap_range

    def update(self, other):
        """ Update the current property value with a different one and update the score."""
        assert isinstance(other, NEATProperty)

        if not other.key == self.key:
            logging.debug("Property key mismatch")
            return

        self.evaluated = True

        if math.isnan(self.score):
            self.score = 0.0

        value_differs = not self == other

        # TODO simplify
        if (other.precedence >= self.precedence) and not (
                        other.precedence == NEATProperty.IMMUTABLE and self.precedence == NEATProperty.IMMUTABLE):

            # new precedence is higher than current precedence, update
            self.value = other.value
            self.precedence = other.precedence
            if value_differs:
                self.score += -1.0  # FIXME adjust scoring

                logging.debug("property %s updated to %s." % (self.key, self.value))
            else:
                self.score += +1.0 + 0 * self.precedence * self.weight  # FIXME adjust scoring
                logging.debug("property %s is already %s" % (self.key, self.value))
        elif other.precedence == NEATProperty.IMMUTABLE and self.precedence == NEATProperty.IMMUTABLE:
            if value_differs:
                self.score = -9999.0  # FIXME adjust scoring
                logging.debug("property %s is _immutable_: won't update." % (self.key))
                e = NEATPropertyError('immutable property: %s vs %s' % (self, other), dict(property=[self, other]))
                raise e
            else:
                self.score += +1.0  # FIXME adjust scoring
                logging.debug("property %s is already %s" % (self.key, self.value))
        else:
            if value_differs:
                # property cannot be fulfilled
                self.score += -1.0  # FIXME adjust scoring
                logging.debug("property %s cannot be fulfilled." % (self.key))
            else:
                # update value if numeric value ranges overlap

                self.value = self == other  # comparison returns range intersection
                self.score += +1.0  # FIXME adjust scoring
                logging.debug("range updated for property %s." % (self.key))

        logging.debug("updated %s" % (self))

    def __str__(self):
        return repr(self)

    def __repr__(self):
        if isinstance(self.value, tuple):
            val_str = '%s-%s' % self.value
        else:
            val_str = str(self._value)

        keyval_str = '%s|%s' % (self.key, val_str)
        if not math.isnan(self.score):
            score_str = '%+.1f' % self.score
        else:
            score_str = ''

        if self.precedence == NEATProperty.IMMUTABLE:
            return '[%s]%s' % (keyval_str, score_str)
        elif self.precedence == NEATProperty.REQUESTED:
            return '(%s)%s' % (keyval_str, score_str)
        elif self.precedence == NEATProperty.INFORMATIONAL:
            return '<%s>%s' % (keyval_str, score_str)
        else:
            return '?%s?%s' % (keyval_str, score_str)


class PropertyDict(dict):
    """Convenience class for storing NEATProperties."""

    def __init__(self, iterable={}):
        self.update(iterable, default_precedence=NEATProperty.REQUESTED)

    def __getitem__(self, item):
        if isinstance(item, NEATProperty):
            key = item.key
        else:
            key = item
        return super().__getitem__(key)

    def update(self, iterable, default_precedence=NEATProperty.REQUESTED):
        """ update properties from:
                a dict containing key:value pairs
                an iterable containing neat property objects
                an iterable containing (key, value, precedence) tuples

        TODO
        """
        if isinstance(iterable, dict):
            for k, v in iterable.items():
                self.insert(NEATProperty((k, v), precedence=default_precedence))
        else:
            for i in iterable:
                if isinstance(i, NEATProperty):
                    self.insert(i)
                else:
                    k, v, *l = i
                    if l:
                        precedence = l[0]
                        # TODO initialize score as well
                    self.insert(NEATProperty((k, v), precedence=precedence))

    def intersection(self, other):
        """Return a new PropertyDict containing the intersection of two PropertyDict objects."""
        properties = PropertyDict()
        for k, p in self.items() & other.items():
            properties.insert(p)
            # properties.update({p.key: p.value })
        return properties

    def insert(self, *properties):
        """
        Insert a new NEATProperty tuple into the dict or update an existing one.

        :rtype: None
        """
        for property in properties:
            if not isinstance(property, NEATProperty):
                logging.warning("only NEATProperty objects may be inserted to PropertyDict.")
                return

            if property.key in self.keys():
                self[property.key].update(property)
            else:
                self.__setitem__(property.key, property)

    def insert_dict(self, json_dict={}):
        """ Import a dictionary containing properties

        example insert_dict({'foo':{'value':'bar', 'precedence':0}})
        """
        for key, attr in json_dict.items():
            try:
                neat_property = NEATProperty((key, attr['value']),
                                             precedence=attr.get('precedence', NEATProperty.REQUESTED),
                                             score=attr.get('score', math.nan))
            except KeyError as e:
                raise NEATPropertyError('property import failed') from e

            self.insert(neat_property)

    def insert_json(self, json_str='{}'):
        """ Import a list of JSON encoded properties"""
        try:
            request_properties = json.loads(json_str)
        except json.decoder.JSONDecodeError:
            logging.error('invalid JSON string')
            return
        self.insert_dict(request_properties)

    @property
    def dict(self):
        """ Return a dictionary containing all NEAT property attributes"""
        property_dict = dict()
        for p in self.values():
            property_dict.update(p.dict())
        return property_dict

    @property
    def list(self):
        """ Return a sorted list containing all property objects"""
        property_list = [i.dict() for i in self.values()]
        # TODO sort by score
        return property_list

    def json_old(self, indent=None, with_score=True):
        """deprecated"""
        plist = [i for i in self.list]
        return json.dumps(plist, sort_keys=True, indent=indent)

    def json(self, indent=None, with_score=True):
        return json.dumps(self.dict, sort_keys=True, indent=indent)

    def __repr__(self):
        return '{' + ', '.join([str(i) for i in self.values()]) + '}'


class NEATPolicy(object):
    """NEAT policy representation"""

    def __init__(self, policy_dict={}, name='NA'):
        # set default values
        self.idx = id(self)
        self.name = policy_dict.get('name', name)
        for k, v in policy_dict.items():
            if isinstance(v, str):
                setattr(self, k, v)

        self.priority = int(policy_dict.get('priority', 0))  # TODO not sure if we need priorities

        self.match = PropertyDict()
        match = policy_dict.get('match', {})
        self.match.insert_dict(match)

        self.properties = PropertyDict()
        properties = policy_dict.get('properties', {})
        self.properties.insert_dict(properties)

    def match_len(self):
        """Use the number of match elements to sort the entries in the PIB.
        Entries with the smallest number of elements are matched first."""
        return len(self.match)

    def compare(self, properties, strict=True):
        """Check if the match properties are completely covered by the properties of a query.

        If strict flag is set match only properties with precedences that are higher or equal to the precedence
        of the corresponding match property.
        """

        # always return True if the match field is empty (wildcard)
        if not self.match:
            return True

        # find intersection
        matching_props = self.match.items() & properties.items()
        if strict:
            # ignore properties with a lower precedence than the associated match property
            return bool({k for k, v in matching_props if properties[k].precedence >= self.match[k].precedence})
        else:
            return bool(matching_props)

    def apply(self, properties: PropertyDict):
        """Apply policy properties to a set of candidate properties."""
        for p in self.properties.values():
            logging.info("applying property %s" % p)
            properties.insert(p)

    def __str__(self):
        return "POLICY %s: %s  ==>  %s" % (self.name, self.match, self.properties)

    def __repr__(self):
        return repr({a: getattr(self, a) for a in ['name', 'match', 'properties']})


class NEATCandidate(object):
    """Neat candidate objects store a list of properties for potential NEAT connections.
    They are created after a CIB lookup.

      NEATCandidate.cib: contains the matched cib entry
      NEATCandidate.policies: contains a list of applied policies
    """

    def __init__(self, properties=None):
        # list to store policies applied to the candidate
        self.policies = set()
        self.properties = PropertyDict()
        self.invalid = False

        if properties:
            self.properties = copy.deepcopy(properties)
            # for property in properties.values():
            #    self.properties.insert(property)

    @property
    def score(self):
        return sum(i.score for i in self.properties.values() if not math.isnan(i.score))

    def dump(self):
        print('PROPERTIES: ' + str(self.properties) + ', POLICIES: ' + str(self.policies))

    def __repr__(self):
        return str(self.properties)


class NEATRequest(object):
    """NEAT query"""

    def __init__(self, *properties):
        # super(NEATRequest, self).__init__(properties)
        self.properties = PropertyDict()

        for p in properties:
            self.properties.insert(p)

        # Each NEATRequest contains a list of NEATCandidate objects
        self.candidates = []
        self.cib = None

    def __repr__(self):
        return '<NEATRequest: %d candidates, %d properties>' % (len(self.candidates), len(self.properties))

    def dump(self):
        print(self.properties)
        print('===== candidates =====')
        for i, c in enumerate(self.candidates):
            print('%d: ' % i, end='')
            c.dump()
        print('===== candidates =====')


class PIB(list):
    def __init__(self, policy_dir=None):
        super().__init__()
        self.policies = self
        self.index = {}

        if policy_dir:
            self.load_policies(policy_dir)

    def load_policies(self, policy_dir=POLICY_DIR):
        """Load all policies in policy directory."""
        for filename in os.listdir(policy_dir):
            if filename.endswith(('.policy', '.profile')):
                print('loading policy %s' % filename)
                p = self.load_policy(policy_dir + filename)
                self.register(p)

    def load_policy(self, filename):
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

    def register(self, policy):
        """Register new policy

        Policies are ordered
        """
        # check for existing policies with identical match properties
        if policy.match in [p.match for p in self.policies]:
            logging.warning("Policy match fields already registered. Skipping policy %s" % (policy.name))
            return
        # TODO check for overlaps and split
        self.policies.append(policy)
        # TODO sort on the fly
        self.policies.sort(key=operator.methodcaller('match_len'))
        self.index[policy.idx] = policy

    def lookup_candidates(self, candidates):
        # TODO
        pass

    def lookup_all(self, candidates):
        """ Lookup all candidates in list. Remove invalid candidates """
        for candidate in candidates:
            try:
                applied_policies = self._lookup(candidate.properties, apply=True)
                candidate.policies.update(applied_policies)
            except NEATPropertyError as e:
                candidate.invalid = True
                print('Candidate %d is invalidated due to policy.' % (candidates.index(candidate)))
                logging.debug('invalidated due to: %s' % e.args[0])

        candidates[:] = [c for c in candidates if not c.invalid]

    def _lookup(self, properties, apply=False, remove_matched=False):
        """ Look through all installed policies to find the ones which match the properties of the given candidate.
        If apply is True, append the matched policy properties.
        If remove_matched is True, remove the policy match properties from the candidate.

        Returns all matched policies.
        """

        assert isinstance(properties, PropertyDict)
        logging.debug("matching policies for current candidate:")

        applied_policies = []
        for p in self.policies:
            if p.compare(properties):
                if remove_matched and apply:
                    logging.info("applying profile %s" % p.idx)
                    for key in p.match:
                        del properties[key]
                if apply:
                    p.apply(properties)
                    applied_policies.append(p.idx)
                else:
                    print(p.idx)
        return applied_policies

    def dump(self):
        s = "===== PIB START =====\n"
        for p in self.policies:
            s += str(p) + '\n'
        s += "===== PIB END ====="
        print(s)

    def __repr__(self):
        return 'PIB<%d>' % len(self)

    @property
    def matches(self):
        """Return the match fields of all installed policies"""
        return [p.match for p in self.policies]


class PropertyTests(unittest.TestCase):
    # TODO
    def test_property_logic(self):
        np2 = NEATProperty(('foo', 'bar2'), precedence=NEATProperty.IMMUTABLE)
        np1 = NEATProperty(('foo', 'bar1'), precedence=NEATProperty.REQUESTED)
        np0 = NEATProperty(('foo', 'bar0'), precedence=NEATProperty.INFORMATIONAL)

        # self.assertEqual(numeral, result)
        # unittest.main()


if __name__ == "__main__":
    import code

    np = NEATProperty(('foo', 'bar'))
    pd = PropertyDict()
    pd.insert(np)

    code.interact(local=locals())
