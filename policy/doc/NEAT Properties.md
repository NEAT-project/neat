# NEAT Properties

NEAT properties are essentially `key|value` tuples describing attributes used by the components of the NEAT Policy Manager. NEAT properties are used to express attributes describing the local host and the attached networks, user requirements, or constraints imposed by policies. Examples include interface names, types, supported protocols and parameters, or topology metrics (e.g., available bandwidth).

Each property has a `key` string and `value`. Currently property values can be

  1. a **single** boolean, integer, float or string value, e.g., `2`, `true`, or `"TCP"`. 
  2. a **set** of values `[100, 200, 300, "foo"]`. 
  3. a numeric **range** `{"start":1, "end":10}`.

Each property is further associated with a `precedence` which identifies the "importance" of the property. Specifically, the precedence indicates if the property may be modified by the Policy Manager logic or if it is immutable. Currently two property precedence levels are defined in order of decreasing priority:

+ `[immutable]` (precedence 2) these are mandatory properties whose value cannot be changed.
+ `(requested)` (precedence 1) these are optional properties whose value may be overwritten. A mismatch of such properties will result in a penalty in the ranking within the PM. Such penalties are recorded as the `score` of the property.

In the sequel we use the following notation: we separate the property key/value pair by the `|` character and indicate the property's precedence by the bracket types shown above. We append the score to the brackets and omit it if zero. For example

+  `[transport|TCP]+2`: the transport protocol *must* be "TCP"
+   `(MTU|1500,2000,9000)`: one of the specified MTU values *should* be chosen if possible
+   `(capacity|10-1000)+1`: the interface capacity should be within the numeric range specified by the integers


### Property Operators

Two NEAT properties are considered 'equal' if their key and value attributes are identical. Precedence and scores are ignored when testing for equality. A comparison of two properties yields a boolean result. 

For instance, the comparison `[transport|TCP]+1 == (transport|TCP)+3` is true. Set and range value attributes are also considered equal if their values overlap, i.e., `[transport|TCP,UDP,MPTCP] == [transport|TCP]`, or `[latency|1-100]==[latency|55]`.



A property update is considered successful if the ranges overlap -- the resulting updated property will contain the intersection of the two ranges.


In the course of a lookup in the PM, properties from various sources will be compared and their values may be *updated*. A property's value may *only* be updated by another property whose precedence is greater or equal than itself. A property may only be updated by another property with the same key. When a property is updated it inherits the precedence of the updating property as explained below:



As an example, if an immutable property is requested by an application and this property clashes with the corresponding property in a connection candidate the candidate must be discarded.



In addition, each property is associated with a numeric `score` denoting whether, and how often, a property has been matched. Each time a property is updated its score is increased if its value matched the compared property, and decreased otherwise. The property score is used to determine the most suitable NEAT connection `candidate` for a given request (see below).

