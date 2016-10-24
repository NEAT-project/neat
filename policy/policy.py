import copy
import json
import logging
import numbers
import unittest
import operator

logging.basicConfig(format='[%(levelname)s]: %(message)s', level=logging.DEBUG)

BOLD_START = '\033[1m'
UNDERLINE_START = '\033[4m'
STRIKETHROUGH_START = '\033[9m'
FORMAT_END = '\033[0m'
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
    properties = []
    for key, attr in property_dict.items():

        if isinstance(attr, list):
            # property value is a list and we will need to expand it
            for p in attr:
                properties.extend(dict_to_properties({key: p}))
        else:
            val = attr.get('value', None)
            try:
                neat_property = NEATProperty((key, val),
                                             precedence=attr.get('precedence', NEATProperty.OPTIONAL),
                                             banned=attr.get('banned', []),
                                             score=attr.get('score', 0.0))
            except KeyError as e:
                raise NEATPropertyError('property import failed') from e

            properties.append(neat_property)
    return properties


def properties_to_json(property_array, indent=None):
    property_dict = dict()
    for i in property_array.values():
        property_dict.update(i.dict())
    return json.dumps(property_dict, sort_keys=True, indent=indent)


class PropertyValue(object):
    """
    Property values can be
    1. a single value such as 2, True, or "TCP".
    2. a set of values [100, 200, 300, "foo"]. uses a set() internally
    3. a numeric range {"start":1, "end":10}. uses a tuple internally
    """

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
        # new style min-max numeric range
        elif isinstance(value, (dict,)):
            try:
                self._value = (value['start'], value['end'])
            except KeyError as e:
                print(e)
                raise IndexError("Invalid property range definition")
            self.is_range = True
        # numeric range as tuple
        elif isinstance(value, (tuple,)) and len(value) == 2:
            self._value = value
            self.is_range = True
        # set of values ["TCP", "UDP"]
        elif isinstance(value, (list, set)):
            if len(value) == 1:
                self._value = value.pop()
                self.is_single = True
            else:
                self._value = set(value)
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

        if (self.is_range or self.is_numeric) and (other.is_range or other.is_numeric):
            return self._overlapping_range(other)

        if self.is_set and other.is_range:
            new_set = [i for i in self.value if other.value[0] <= i <= other.value[1]]
            return PropertyValue(new_set)
        if self.is_range and other.is_set:
            new_set = [i for i in other.value if self.value[0] <= i <= self.value[1]]
            return PropertyValue(new_set)

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


    """

    IMMUTABLE = 2
    OPTIONAL = 1

    def __init__(self, keyval, precedence=OPTIONAL, score=0, banned=None):
        self.key = keyval[0]
        self._value = PropertyValue(keyval[1])

        self.precedence = precedence
        self.score = score

        if banned:
            self.banned = [PropertyValue(b) for b in banned]
        else:
            self.banned = []

        # set if property was compared or updated during a lookup
        self.evaluated = False

        # TODO check if value is in banned list

    @property
    def value(self):
        return self._value.value

    @value.setter
    def value(self, value):
        self._value = PropertyValue(value)

        # if new_value.is_numeric and self._value.is_numeric:
        #     overlap =  self._range_overlap(new_value.value)
        #     self._value = PropertyValue()
        #
        # old_value = self._value
        # self._value = value
        #
        #
        # if isinstance(old_value, (tuple, numbers.Number)) and isinstance(value, (tuple, numbers.Number)):
        #     # FIXME ensure that tuple values are numeric
        #     new_value = self._range_overlap(old_value)
        #     if new_value:
        #         self._value = new_value

    @property
    def property(self):
        return self.key, self.value

    def dict(self):
        """Return a dict for JSON export"""
        json_dict = {
            self.key: dict(value=self.value, precedence=self.precedence, score=self.score, evaluated=self.evaluated)}
        return json_dict

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
        """Return true if a single value is in range, or if two ranges have an overlapping region."""
        return self & other

    def update(self, other):
        """ Update the current property value with a different one and update the score."""
        assert isinstance(other, NEATProperty)

        if not other.key == self.key:
            logging.debug("Property key mismatch")
            return

        old_self_str = str(self)
        other_str = str(other)

        self.evaluated = True
        self.banned.extend(other.banned)

        value_match = self == other

        # property with the higher precedence determines the new property value and new precedence
        # if both precedences are optional, the other property sets the new property value and new precedence
        # if both precedences are immutable, we raise an exception if the values differ

        if value_match:
            self.score += other.score  # TODO adjust scoring
            self.value = value_match
            self.precedence = max(self.precedence, other.precedence)
        else:
            if other.precedence == NEATProperty.IMMUTABLE and self.precedence == NEATProperty.IMMUTABLE:
                err_str = "%s <-- %s: immutable property" % (self, other)
                logging.debug(err_str)
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
        """Pretty print NEAT properties
        """
        if self._value.is_range:
            # min-max range
            val_str = '%s-%s' % self.value
        elif self._value.is_set:
            val_str = ','.join([str(i) for i in self.value])
        elif self.value is None:
            val_str = ''
        else:
            val_str = str(self._value)

        keyval_str = '%s|%s' % (self.key, val_str)

        if self.banned:
            # strikethrough banned values
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
        score_str = score_str.translate(SUB)

        if self.precedence == NEATProperty.IMMUTABLE:
            property_str = '[%s]%s' % (keyval_str, score_str)
        elif self.precedence == NEATProperty.OPTIONAL:
            property_str = '(%s)%s' % (keyval_str, score_str)
        else:
            property_str = '?%s?%s' % (keyval_str, score_str)

        if self.evaluated:
            property_str = UNDERLINE_START + property_str + FORMAT_END

        return property_str


class PropertyArray(dict):
    def __init__(self, *properties):
        self.add(*properties)

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

    def intersection(self, other):
        return self & other

    @property
    def score(self):
        return sum((s.score for s in self.values() if s.evaluated)), sum((s.score for s in self.values() if not s.evaluated))  # FIXME only if s.evaluated?

    def dict(self):
        """ Return a dictionary containing all contained NEAT property attributes"""
        property_dict = dict()
        for p in self.values():
            property_dict.update(p.dict())
        return property_dict

    def __repr__(self):
        # sort alphabetically by property key
        str_list = [str(i) for i in sorted(list(self.values()), key=lambda v: v.key.lower())]
        return '├─' + '──'.join(str_list) + '─┤'


class PropertyMultiArray(dict):
    def __init__(self, *properties):
        # FIXME this needs improvement
        self.add(*properties)

    def __getitem__(self, key):
        item = super().__getitem__(key)
        return [i for i in item]

    def __contains__(self, item):
        # check if item is already in the array
        return any(item.eq(property) for property in self.get(item.key, []))

    def add(self, *properties):
        """
        Insert a new NEATProperty object into the dict. If the property key already exists make it a multi property list.
        """

        for property in properties:
            if isinstance(property, list):
                for p in property:
                    self.add(p)
            elif isinstance(property, NEATProperty):
                if property.key in self.keys() and property not in self:
                    super().__getitem__(property.key).append(property)
                else:
                    self[property.key] = [property]
            elif not isinstance(property, NEATProperty):
                logging.error(
                    "only NEATProperty objects may be added to PropertyDict: received %s instead" % type(property))
                return

    def expand(self):
        pas = [PropertyArray()]
        for k, ps in self.items():
            tmp = []
            while len(pas) > 0:
                pa = pas.pop()
                for p in ps:
                    pa_copy = copy.deepcopy(pa)
                    pa_copy.add(p)
                    tmp.append(pa_copy)
            pas.extend(tmp)
        return pas

    def __repr__(self):
        slist = []
        for i in self.values():
            slist.append(str(i))
        return '╠═' + '══'.join(slist) + '═╣'  # UTF8


if __name__ == "__main__":
    pma = PropertyMultiArray()

    import code
    code.interact(local=locals(), banner='policy')

