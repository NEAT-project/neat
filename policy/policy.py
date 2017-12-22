import copy
import itertools
import json
import math
import numbers
import shutil

from pmdefaults import *
from pmdefaults import STYLES, CHARS

SUB = str.maketrans("0123456789+-", "₀₁₂₃₄₅₆₇₈₉₊₋")


class NEATPropertyError(Exception):
    pass


class ImmutablePropertyError(NEATPropertyError):
    pass


class InvalidPropertyError(NEATPropertyError):
    pass


def json_to_properties(json_str):
    """ Import a list of JSON encoded NEAT properties

    Return a list of NEAT PropertyArray objects if json_str is an array. Convert to array otherwise.

    example: json_to_properties('[{"foo":{"value":"bar", "precedence":0}}]')

    """
    try:
        property_dict = json.loads(json_str)
    except json.decoder.JSONDecodeError as e:
        logging.error(json_str + ' is not a valid JSON string: ' + str(e))
        raise InvalidPropertyError('invalid JSON string: ' + str(e))

    property_array_list = []

    if not isinstance(property_dict, list):
        property_dict = [property_dict]
        logging.warning("received JSON string is not in an array. Converting...")

    for pd in property_dict:
        property_array_list.append(dict_to_properties(pd))
    return property_array_list


def dict_to_properties(property_dict):
    """ Import a dictionary containing properties

    example: dict_to_properties({'foo':{'value':'bar', 'precedence':0}})

    """
    if not isinstance(property_dict, dict):
        raise InvalidPropertyError("not a dict")

    properties = []
    for key, attr in property_dict.items():

        if isinstance(attr, list):
            # property value is a list and we will need to expand it
            for p in attr:
                properties.extend(dict_to_properties({key: p}))
        else:
            try:
                val = attr.get('value', None)
            except AttributeError as e:
                raise NEATPropertyError('Property dictionary item invalid') from e

            try:
                neat_property = NEATProperty((key, val),
                                             precedence=attr.get('precedence', NEATProperty.OPTIONAL),
                                             banned=attr.get('banned', []),
                                             evaluated=attr.get('evaluated', False),
                                             score=attr.get('score', 0.0))
            except KeyError as e:
                raise NEATPropertyError('property import failed') from e

            properties.append(neat_property)
    return properties


def properties_to_json(property_array, indent=None):
    property_dict = dict()
    for i in property_array.values():
        property_dict.update(i.dict(full=True))
    return json.dumps(property_dict, sort_keys=True, indent=indent)


def to_inf(inf_str):
    # TODO
    if isinstance(inf_str, str) and inf_str.lower() == 'inf':
        return math.inf
    else:
        return inf_str


class PropertyValue(object):
    """
    Property values can be
    1. a single value such as 2, True, or "TCP".
    2. a set of values [100, 200, 300, "foo"]. uses a set() internally
    3. a numeric range {"start":1, "end":10}. uses a tuple internally
    """
    ANY = None

    def __init__(self, value):
        self._value = None

        self.is_single = False
        self.is_numeric = False
        self.is_set = False
        self.is_range = False

        self.value = value

    @property
    def value(self):
        return self._value

    def __to_inf(self, value):
        str_value = str(value).strip().lower()
        if str_value in ['inf', '-inf', 'infinity', '-infinity']:
            if str_value.startswith('-'):
                value = -math.inf
            else:
                value = math.inf
        return value

    @value.setter
    def value(self, value):

        self.is_single = False
        self.is_set = False
        self.is_range = False
        self.is_numeric = False

        if isinstance(value, (int, float, bool, str)):
            self._value = value
            self.is_single = True
            self.is_numeric = True if isinstance(value, numbers.Number) else False
        # min-max numeric range
        elif isinstance(value, (dict,)):
            try:
                range_start, range_end = self.__to_inf(value['start']), self.__to_inf(value['end'])
                range_end - range_start > 0
                self._value = (range_start, range_end)
            except KeyError as e:
                print(e)
                raise IndexError("Invalid property range definition")
            except TypeError as e:
                print(e)
                raise IndexError("Invalid property range definition: ranges should be numeric")
            self.is_range = True
        # old-style numeric ranges stored as tuples
        # deprecated
        elif isinstance(value, (tuple,)) and len(value) == 2:
            self._value = value
            self.is_range = True
        # sets of values ["TCP", "UDP"]
        elif isinstance(value, (list, set)):
            if len(value) == 1:
                self._value = value.pop()
                self.is_single = True
            else:
                try:
                    self._value = set(value)
                except TypeError:
                    import code
                    code.interact(local=locals(), banner='policy error')
                self.is_set = True
        elif isinstance(value, PropertyValue):
            self._value = value._value
            self.is_single = value.is_single
            self.is_numeric = value.is_numeric
            self.is_set = value.is_set
            self.is_range = value.is_range
        elif isinstance(value, type(None)):
            self._value = None
        else:
            raise NEATPropertyError("invalid property value %s (type %s)" % (value, type(value)))

        if self.is_range:
            # make sure that range values are numeric
            try:
                self._value = tuple((float(i) for i in self._value))
            except ValueError as e:
                raise IndexError("Property value range is not numeric")

            if self._value[0] > self._value[1]:
                raise IndexError("Invalid property range (start>end)")
            self.is_numeric = True

    def __and__(self, other):

        if not isinstance(other, PropertyValue):
            other = PropertyValue(other)

        if self.value == PropertyValue.ANY:
            return other
        if other.value == PropertyValue.ANY:
            return self

        if (self.is_range or self.is_numeric) and (other.is_range or other.is_numeric):
            return self._overlapping_range(other)

        if self.is_set and other.is_range:
            new_set = [i for i in self.value if other.value[0] <= i <= other.value[1]]
            return PropertyValue(new_set)
        if self.is_range and other.is_set:
            new_set = [i for i in other.value if self.value[0] <= i <= self.value[1]]
            return PropertyValue(new_set)
        # FIXME check for TypeError? https://github.com/NEAT-project/neat/issues/245

        if self.is_set or other.is_set:
            return self._overlapping_set(other)

        if self.value == other.value:
            return self.value
        else:
            return False

    def _overlapping_set(self, other):
        """
        check for overlapping set values

        """

        assert isinstance(other, PropertyValue)

        if self.is_single:
            self_set = {self.value}
        else:
            self_set = set(self.value)
        other_set = {other.value} if other.is_single else set(other.value)
        new_set = self_set & other_set

        if len(new_set) == 1:
            return PropertyValue(new_set.pop())
        elif len(new_set) == 0:
            # FIXME is there a better way to handle this?
            raise InvalidPropertyError("set is empty")
        else:
            return PropertyValue(new_set)

    def _overlapping_range(self, other):
        """
        check for overlapping numeric ranges

        """
        assert isinstance(other, PropertyValue)

        # create a tuple if one of the ranges is just a single numerical value
        if self.is_range:
            self_range = self.value
        elif self.is_single and self.is_numeric:
            self_range = (self.value, self.value)
        else:
            return False

        if other.is_range:
            other_range = other.value
        elif other.is_single and other.is_numeric:
            other_range = (other.value, other.value)
        else:
            return False

        # check if ranges have an overlapping region
        overlap = other_range[0] <= self_range[1] and other_range[1] >= self_range[0]

        if not overlap:
            return False
        else:
            # return actual range
            overlap_range = max(other_range[0], self_range[0]), min(other_range[1], self_range[1])

            if overlap_range[0] == overlap_range[1]:
                return PropertyValue(overlap_range[0])
            else:
                return PropertyValue(overlap_range)

    def __repr__(self):
        return str(self.value)


class NEATProperty(object):
    """
    The basic unit for representing properties in NEAT. NEATProperties are (key,value) tuples.

    NEATProperty keys are always in lower case
    """

    IMMUTABLE = 2
    OPTIONAL = 1
    BASE = 0

    def __init__(self, key_val, precedence=OPTIONAL, score=0, banned=None, evaluated=False):
        self._key = ''
        self.key = key_val[0]
        self._value = PropertyValue(key_val[1])

        self.precedence = precedence
        self.score = score

        # TODO implement banned values
        if banned:
            self.banned = [PropertyValue(b) for b in banned]
        else:
            self.banned = []

        # set if property was compared or updated during a lookup
        self.evaluated = evaluated

    @property
    def value(self):
        return self._value.value

    @value.setter
    def value(self, value):
        self._value = PropertyValue(value)

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, value):
        self._key = str(value).lower()

    @property
    def property(self):
        return self.key, self.value

    def dict(self, full=False):
        """
        Return a dict representation of the NEATProperty e.g. for JSON export.
        If extended is set also include default values.
        """

        d = dict()

        if isinstance(self.value, tuple):
            d['value'] = {'start': self.value[0], 'end': self.value[1]}
        elif isinstance(self.value, set):
            # sets are not supported in JSON so convert these to a list
            d['value'] = list(self.value)
        else:
            d['value'] = self.value

        if full:
            d['precedence'] = self.precedence
            d['score'] = self.score
            d['evaluated'] = self.evaluated
        else:
            if self.precedence != DEFAULT_PRECEDENCE: d['precedence'] = self.precedence
            if self.score != DEFAULT_SCORE: d['score'] = self.score
            if self.evaluated != DEFAULT_EVALUATED: d['evaluated'] = self.evaluated

        return {self.key: d}

    def __iter__(self):
        for p in self.property:
            yield p

    def __hash__(self):
        # define hash for set comparisons
        return hash(self.key)

    def eq(self, other):
        if (self.key, self.value, self.precedence) == (other.key, other._value, other.precedence):
            return True
        else:
            return False

    def __add__(self, other):
        """
        Create a new property by updating the first one with the second. Returns a new NEATProperty object.
        """

        # experimental: reverse comparison order if precedence is zero.
        # Used to implement policies with default properties.
        if other.precedence == NEATProperty.BASE:
            new_prop = copy.deepcopy(other)
            new_prop.update(self, evaluate=False)
            return new_prop

        new_prop = copy.deepcopy(self)
        new_prop.update(other)
        return new_prop

    def __and__(self, other):
        """
        Return true if a single value is in range, or if two ranges have an overlapping region.
        """
        assert isinstance(other, NEATProperty)
        return self._value & other._value

    def __eq__(self, other):
        """Return true if a single value is within range, or if two ranges have an overlapping region. """
        try:
            return self & other
        except InvalidPropertyError:
            return False

    def update(self, other, evaluate=True):
        """ Update the current property value with a different one and update the score."""
        assert isinstance(other, NEATProperty)

        if not other.key == self.key:
            logging.debug("Property key mismatch")
            return

        old_self_str = str(self)
        other_str = str(other)

        self.evaluated = evaluate
        self.banned.extend(other.banned)

        value_match = self == other

        # property with the higher precedence determines the new property value and new precedence
        # if both precedences are optional, the other property determines the new property value and new precedence
        # if both precedences are immutable, we raise an exception if the property values differ

        if value_match:
            self.score += other.score  # TODO adjust scoring
            self.value = value_match
            self.precedence = max(self.precedence, other.precedence)
        else:
            if other.precedence == NEATProperty.IMMUTABLE and self.precedence == NEATProperty.IMMUTABLE:
                err_str = "%s <-- %s: immutable property" % (self, other)
                # logging.debug(err_str)
                raise ImmutablePropertyError(err_str)
            elif other.precedence >= self.precedence:
                self.score = other.score
                self.value = other.value
                self.precedence = other.precedence
            else:
                # keep current value
                pass

                # logging.debug("%s + %s -> %s" % (old_self_str, other_str, self))

    def __str__(self):
        return repr(self)

    def __repr__(self):
        """
        Pretty print NEAT properties
        """
        if self._value.is_range:
            # min-max range
            val_str = '%s-%s' % self.value
        elif self._value.is_set:
            val_str = ','.join([str(i) for i in self.value])
        elif self.value is None:
            # empty value matches ANY property value
            val_str = '*'
        else:
            val_str = str(self._value)

        keyval_str = '%s|%s' % (self.key, val_str)

        if self.banned:
            # strike-through banned values
            banned_str = ','.join([u'\u0336'.join(i.value) + u'\u0336' for i in self.banned])
            # fix non UTF environments (TODO there should be a better way to handle this)
            if len(val_str) > 0:
                keyval_str += ','
            keyval_str += banned_str

        if self.score > 0.0:
            score_str = '%+.1f' % self.score
        elif self.score < 0.0:
            score_str = '%-.1f' % self.score
        else:
            score_str = ''
        # use subscript UTF8 characters
        score_str = STYLES.BOLD_START + score_str.translate(SUB) + STYLES.BOLD_END

        if self.evaluated:
            keyval_str = STYLES.UNDERLINE_START + keyval_str + STYLES.UNDERLINE_END

        if self.precedence == NEATProperty.IMMUTABLE:
            property_str = '[%s]%s' % (keyval_str, score_str)
        elif self.precedence == NEATProperty.OPTIONAL:
            property_str = '(%s)%s' % (keyval_str, score_str)
        elif self.precedence == NEATProperty.BASE:
            property_str = '%s%s' % (keyval_str, score_str)
        else:
            property_str = '?%s?%s' % (keyval_str, score_str)

        if self.key.startswith('__'):
            property_str = STYLES.LIGHT_GRAY_START + property_str + STYLES.FORMAT_END
        else:
            property_str = STYLES.DARK_GRAY_START + property_str + STYLES.FORMAT_END

        return property_str


class PropertyArray(dict):
    def __init__(self, *properties):
        self.add(*properties)

        # dict to store some auxiliary information
        self.meta = dict()

    def add(self, *properties):
        """
        Insert a new NEATProperty object into the array. If the property key already exists update it.
        """

        for p in properties:
            if isinstance(p, NEATProperty):
                if p.key in self.keys():
                    self[p.key].update(p)
                else:
                    self[p.key] = p
            else:
                logging.error(
                    "only NEATProperty objects may be added to PropertyDict: received %s instead" % type(p))
                raise NEATPropertyError("cannot add %s" % type(p))

    @staticmethod
    def from_dict(d):
        return PropertyArray(*dict_to_properties(d))

    def __add__(self, other):
        """ Return a new PropertyArray constructed using PropertyArray1 + PropertyArray2 """
        diff = self ^ other
        inter = self & other
        return PropertyArray(*diff.values(), *inter.values())

    def __and__(self, other):
        """Return new PropertyArray containing the intersection of two PropertyArray objects."""
        inter = (self[k] + other[k] for k in self.keys() & other.keys())
        return PropertyArray(*inter)

    def __xor__(self, other):
        # return symmetric difference, i.e., non overlapping properties
        diff = [k for k in self.keys() ^ other.keys()]
        return PropertyArray(*[other[k] for k in diff if k in other], *[self[k] for k in diff if k in self])

    def __le__(self, other):
        """Check if current properties are a full subset of another PropertyArray"""
        if isinstance(other, PropertyArray):
            return set(self.values()) <= set(other.values())
        else:
            return set(self.values()) <= other

    def intersection(self, other):
        return self & other

    @property
    def score(self):
        """Return the sum of scores of all array properties that have their `evaluated` flag set."""
        return sum((s.score for s in self.values() if s.evaluated)), sum(
            (s.score for s in self.values() if not s.evaluated))

    @property
    def uid(self):
        # TODO generate UID for candidates
        return 1234

    def dict(self):
        """ Return a dictionary containing all contained NEAT property attributes"""
        property_dict = dict()
        for p in self.values():
            property_dict.update(p.dict())
        return property_dict

    def __repr__(self):
        # sort alphabetically by property key
        str_list = [str(i) for i in sorted(list(self.values()), key=lambda v: v.key.lower())]
        j = CHARS.DASH * 2
        return '├─' + j.join(str_list) + '─┤'


def __merge_properties(properties):
    """
    Merge list of properties into a list for adding into MultiArray. If several properties with identical key exit,
    they will be added into a joint list.
    """
    keys = {i.key for i in properties}
    new_property_list = []
    single_property_pa = PropertyArray()

    for k in keys:
        pa_list = [PropertyArray(p) for p in properties if p.key == k]
        if len(pa_list) == 1:
            single_property_pa.add(pa_list[0][k])
        else:
            new_property_list.append(pa_list)
    return new_property_list + [single_property_pa]


class PropertyMultiArray(list):
    def __init__(self, *properties):
        # FIXME this needs improvement
        self.add(*properties)

    def add(self, *properties):
        for property in properties:
            if isinstance(property, list):
                if all([isinstance(i, PropertyArray) for i in property]):
                    self.append(property)
                else:
                    logging.error("list must contain property arrays")
            elif isinstance(property, PropertyArray):
                self.append([property])
            elif isinstance(property, NEATProperty):
                self.append([PropertyArray(property)])
            else:
                logging.error(
                    "Cannot add %s objects to PropertyArrays" % type(property))
                return

    def expand(self):
        # FIXME this is called too often
        expanded_pas = []

        for pa_product in itertools.product(*self):
            pa = PropertyArray()
            for p in pa_product:
                tmp = copy.deepcopy(p)  # FIXME otherwise method alters the properties
                pa.add(*tmp.values())
            expanded_pas.append(pa)
        return expanded_pas

    def list(self):
        new_list = []
        for l in list(self):
            new_list.append([pa.dict() for pa in l])
        return new_list

    @staticmethod
    def from_json(j):
        pma_list = json.loads(j)
        pma = PropertyMultiArray()
        for l in pma_list:
            if isinstance(l, dict):
                pa = [PropertyArray.from_dict(l)]
            elif isinstance(l, list):
                pa = [PropertyArray.from_dict(pa) for pa in l]
            else:
                pa = []
            pma.add(pa)
        return pma

    def __repr__(self):
        j = CHARS.LINE_SEPARATOR * 2
        return '╠═' + j.join([str(i) for i in self]) + '═╣'  # UTF8


# TODO move to pm_util ############
def term_separator(text='', line_char=CHARS.LINE_SEPARATOR, offset=0):
    """
    Get a separator line with the width of the terminal with a centered text
    """

    # Get the width of the terminal
    ts = shutil.get_terminal_size()
    tcol = ts.columns - offset

    if text: text = ' %s ' % text

    tlen = len(text)

    s = line_char * int((tcol - tlen) / 2) + text + line_char * int((tcol - tlen) / 2)
    # pad right
    s += max(tcol - len(s), 0) * line_char
    return s


if __name__ == "__main__":
    pa = PropertyArray()
    pb = PropertyArray()
    pc = PropertyArray()

    pa.add(NEATProperty(('x', 1)))
    pa.add(NEATProperty(('y', 1)))
    pb.add(NEATProperty(('x', 2)))
    pb.add(NEATProperty(('v', 1)))
    pc.add(NEATProperty(('a', 1)))

    pp = PropertyMultiArray()
    pp.append(pc)

    ppp = PropertyMultiArray()
    ppp.add(pa, [pb, pc])

    import code

    code.interact(local=locals(), banner='policy')
