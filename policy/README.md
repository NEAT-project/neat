# Policy Manager

**DRAFT**

# Quick Start

To start the policy manager simply run:

```
python3.5 ./neatpmd.py --cib ./cib/sdntest/ --pib ./pib/sdntest

```

in the `neat/policy` directory. The `--cib` and `--pib` options specify the respective locations of the CIB and the PIB.

## NEAT properties

NEAT properties are essentially `key|value` tuples describing attributes used by the components of the NEAT Policy Manager. A property can be used  to describe attributes of the system, e.g., known protocol, interface characteristics in the CIB, or to define constraints through policies.

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



## NEAT Policies

__This needs to be updated__

Policies are based around NEAT properties. Each policy contains the following entities:

+ `match`: object containing the set of properties which should trigger the policy. A policy is triggered if *all* of these properties are matched. An empty match field will match *all* properties of a candidate. Match field properties are matched only against properties whose precedence is equal or higher than their own. 
+ `properties`: object containing a set of properties which should be applied to the connection candidate (if feasible given the property precedences).

### NEAT Candidates

`NEATCandidate` objects are used to represent a candidate connections which are be passed to the NEAT logic. Each candidate is comprised of a number of properties aggregated from the candidate request, the CIB, and PIB (see below). Each property is associated with a score, indicating if the corresponding value was fulfilled during the lookups. An undefined score (NaN) indicates that the PM did not have sufficient information to evaluate the property. If a candidate includes`immutable` properties with undefined scores the NEAT logic is responsible to ensure that these are can be fulfilled (An example of such a property would be security)

After each call the PM returns a ranked list of candidates. 
 
## NEAT Requests

A *NEAT Request* is an object containing a set of `NEATProperties` requested for a connection by an NEAT enabled application. In addition, the object includes a list of connection `candidates` (`NEATCandidate`) whose properties match a subset of the requested properties. The candidate list is populated during the CIB lookup phase and is ranked according to the associated property scores.

Each NEAT request is processed in three steps:

1. **Profile Lookup**: the request properties are compared to all profile entries in the PIB. Whenever a profile entry is matched, the corresponding match property in the request is *replaced* with the associated profile properties. Profiles are specified using the same format as policies.
 
2. **CIB Lookup**: the request properties are compared against each entry in the CIB. The properties of a candidate are the union of the request and CIB entry property sets. Specifically, the properties are obtained by overlaying the request properties with the properties of a single CIB entry and updating the *intersection* of the two property sets with corresponding the values from the CIB entry properties.
The *N* entries with the largest aggregate score are appended to the candidate list.

3. **PIB Lookup**: For each candidate the PM iterates through all PIB policies and compares the match properties with the candidates properties. A policy is said to *match* a candidate whenever *all* of its match properties are found in the candidate properties. PIB entries are matched with a *shortest match first* strategy, i.e., policies with the smallest number of `match` properties are applied first. Subsequent, policies will *overwrite* any perviously applied policy properties. Conflicting policies must be identified by the NEAT logic.


## CIB format

[See CIB docs](doc/CIB format.md)



# Example
 
 
## Jupyter Notebook 

__This needs to be updated__

For a detailed walkthrough example see the [**Policy Manager Jupyter notebook**](neat_policy_example.ipynb).


## running the PM


To start the policy manager run:

```
$ ./neatpmd.py --cib ./cib/sdntest/ --pib ./pib/sdntest

```

in the `neat/policy` directory. The `--cib` and `--pib` options specify the respective locations of the CIB and the PIB. By default the PM will create a Unix domain socket located at `~/.neat/neat_pm_socket`, where it will listen for JSON strings containing application requests, and it will output the list of generated candidates.

We can test `neatpmd.py` using the `socat` utility:

```
$ JSON='{"MTU": {"value": [1500, Infinity]}, "low_latency": {"precedence": 2, "value": true}, "remote_ip": {"precedence": 2, "value": "10:54:1.23"}, "transport": {"value": "TCP"}}'
$ echo $JSON | socat -d - UNIX-CONNECT:$HOME/.neat/neat_pm_socket
``` 
or if reading from a file:

``` 
$ socat -d -d -d  FILE:request.json UNIX-CONNECT:$HOME/.neat/neat_pm_socket
``` 


The PM will output a JSON string containing the connection candidates (two of them for the given example) into the out pipe. 

```
[{"MTU": {"precedence": 2, "score": 2.0, "value": 9600}, "TCP_window_scale": {"precedence": 1, "score": NaN, "value": true}, "capacity": {"precedence": 2, "score": 1.0, "value": 10000}, "dns_name": {"precedence": 0, "score": NaN, "value": "backup.example.com"}, "interface": {"precedence": 2, "score": NaN, "value": "en0"}, "interface_latency": {"precedence": 2, "score": NaN, "value": [0.0, 40.0]}, "is_wired": {"precedence": 2, "score": 1.0, "value": true}, "local_ip": {"precedence": 2, "score": NaN, "value": "10.2.0.1"}, "remote_ip": {"precedence": 2, "score": 1.0, "value": "10.1.23.45"}, "transport": {"precedence": 0, "score": NaN, "value": "TCP"}, "transport_TCP": {"precedence": 1, "score": NaN, "value": true}}, {"MTU": {"precedence": 2, "score": 0.0, "value": 1500}, "TCP_window_scale": {"precedence": 1, "score": NaN, "value": true}, "capacity": {"precedence": 2, "score": 1.0, "value": 40000}, "interface": {"precedence": 2, "score": NaN, "value": "en1"}, "interface_latency": {"precedence": 2, "score": 1.0, "value": 35}, "is_wired": {"precedence": 2, "score": 1.0, "value": true}, "local_ip": {"precedence": 2, "score": NaN, "value": "192.168.1.2"}, "remote_ip": {"precedence": 2, "score": NaN, "value": "10.1.23.45"}, "transport_TCP": {"precedence": 1, "score": 1.0, "value": true}, "transport_UDP": {"precedence": 0, "score": NaN, "value": true}}]
```

