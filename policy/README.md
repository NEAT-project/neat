# Policy Manager

**INITIAL ALPHA**

## NEAT properties

NEAT properties are `key|value` tuples describing attributes used within the NEAT Policy Manager. Properties can function as a constraint, e.g., in a policy, or as a statement, e.g., in the CIB.

Each property is associated with a `level` or type which identifies the "importance" of the property. Specifically the level indicates if the property may be modified by the Policy Manager logic. Currently three property levels are defined in order of decreasing precedence:

+ `[immutable]` these are mandatory properties whose value cannot be changed.
+ `(requested)` these are optional properties whose value may be overwritten. A mismatch of such an requested attribute will reduce the `score` of the property (see below).
+ `<informational>` these are properties which have an informational nature. NEAT logic may choose to ignore these.

 
<img src="https://rawgit.com/NEAT-project/neat/master/policy/doc/properties.svg" width="220"/>


Two NEAT properties are considered 'equal' if their key and value attributes are identical, i.e., levels and scores are ignored when testing for equality. A comparison of two properties always yields a boolean result.


In the course of a lookup in the PM, properties from various sources will be compared and their values may be *updated*. A property's value may *only* be updated by another property whose level is greater or equal than itself. A property may only be updated by another property with the same key. When a property is updated it inherits the level of the updating property as illustrated below:

  <img src="https://rawgit.com/NEAT-project/neat/master/policy/doc/properties_example.svg" width="380"/>

As an example, if an immutable property is requested by an application and this property clashes with the corresponding property in a connection candidate the candidate must be discarded.



In addition, each property is associated with a numeric `score` denoting whether, and how often, a property has been matched. Each time a property is updated its score is increased if its value matched the compared property, and decreased otherwise. The property score is used to determine the most suitable NEAT connection candidate for a given request (see below).

### Numeric property ranges

In addition to single values (boolean, integer, float, ...) the value of a property may be specified as a numeric two-tuple to indicate a range, e.g. `(5,30.1)` or `(100,inf)`. Single numeric values are viewed as a range with a length of one.

When comparing properties containing range values, two properties are considered "equal" if their ranges overlap. A property update is considered successful if the ranges overlap - the resulting updated property will contain the intersection of the two ranges.

## NEAT Policies

Policies are based around NEAT properties. Each policy contains the following entities:

+ `match`: contains an object describing the properties which should trigger the policy. An empty match field will match *all* properties of a candidate. Match field properties are matched only against properties whose level is equal or higher than their own. 
+ `properties`: contains an object which lists a set of new properties which should be applied to the connection (if possible given the property levels).

### NEAT Candidates

`NEATCandidate` objects are used to represent a  candidate connections which will be passed to the NEAT logic. 

## NEAT Requests

A *NEAT Request* is an object containing a set of `NEATProperties` requested for a connection by an NEAT enabled application. In addition, the object includes a list of connection `candidates` (`NEATCandidate`) whose properties match a subset of the requested properties. The candidate list is populated during the CIB lookup phase and is ranked according to the associated property scores.

Each NEAT request is processed in two steps:

1. **CIB Lookup**: the request properties are compared against each entry in the CIB. The properties of a candidate are the union of the request and CIB entry property sets. Specifically, the properties are obtained by overlaying the request properties with the properties of a single CIB entry and updating the *intersection* of the two property sets with corresponding the values from the CIB entry properties.

The *N* entries with the larges aggregate score are appended to the candidate list.

2. **PIB Lookup**: For each candidate the PM iterates through all PIB policies and compares the match properties with the candidates properties. A policy is said to *match* a candidate whenever *all* of its match properties are found in the candidate properties. PIB entries are matched with a *shortest match first* strategy, i.e., policies with the smallest number of `match` properties are applied first. Subsequent, policies will *overwrite* any perviously applied policy properties. Conflicting policies must be identified by the NEAT logic.


## CIB format

The CIB is made up of three repositories

+ `local` (L)
+ `connection` (C)
+ `remote` (R)

TODO

# Example
 
For an example see the [Jupyter notebook](doc/neat_policy_example.ipynb) in the `doc` directory.
