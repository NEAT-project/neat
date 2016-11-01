# Properties

A property in NEAT may either express a requirement or it may express a desire
from the application with regards to the service provided by the transport
layer.

A property takes the form of a JSON object. A set of properties is contained
within one JSON object. Below is an example of a JSON object with one property:

```javascript
{
    "property_name": {
        value: "property_value",
        precedence: 1
    }
}
```

Note that all examples of properties will be specified inside a JSON object.

Properties have a name, a value, and a precedence. A string is always used for
the name of a property. The value of a property may be either a boolean, a
string, an integer, a floating point number, an array, or an interval. Each
property expects only one specific type.

The properties are sent to the Policy Manager (if present), which will return a
list containing a list of candidates, which is ordered by how good the
candidate matches the request from the application. Each candidate specifies a
given setting for each property. NEAT will use the properties specified in each
candidate when trying to set up a new connection.

Some properties are set by NEAT based on parameters to function calls. Other
properties must be set manually with the `neat_set_property` function.

## Application property reference

These are properties that may be set by the application.

#### transport

**Type**: Array

Specifies an array of transport protocols that may be used. An application may
specify either one protocol with precedence 2, or multiple protocols with
precedence 1.

**Note**: May not be queried with `neat_get_property` before execution of the
`on_connected` callback. When querying this property, the returned value is a
string describing the actual transport in use.

**Note**: Applications should avoid specifying the protocol(s) to use directly,
and instead rely on the Policy Manager to make a decision on what protocol(s)
to use based on other properties. The `transport` property should only be used
for systems without a Policy Manager, or if the choice of transport protocol is
strictly mandated by the application protocol.


**Example 1**: Multiple protocols

```javascript
{
    "transport": [
        {
            "value": "SCTP",
            "precedence": 1
        },
        {
            "value": "TCP",
            "precedence": 1
        }
    ]
}
```

**Example 2**: One protocol

```javascript
{
    "transport": [
        {
            "value": "UDP",
            "precedence": 2
        }
    ]
}
```

**Available protocols**:

- SCTP
- SCTP/UDP (SCTP tunneled over UDP)
- TCP
- UDP
- UDP-Lite

#### security

**Type**: Boolean

Specifies whether the connection should be encrypted or not. With precedence 2,
NEAT will only report the connection as established if it was able to connect
and the (D)TLS handshake succeeds. With precedence 1, NEAT may still attempt to
establish an unencrypted connection.

## Inferred properties

These are properties that are inferred during connection setup and subsequently
sent to the Policy Manager. Applications should not set these directly.

#### interfaces

**Type**: Array

Specifies a list of available interfaces that may be used for connections. The
Policy Manager may not use all interfaces in this list.

This property is inferred during the `neat_open` call. Do not set this property
manually.

#### domain_name

**Type**: String

Specifies the name of the remote endpoint to connect to with the `neat_open` call.

This property is inferred from the `name` parameter of `neat_open` call. Do not
set this property manually.

#### port

**Type**: Integer

This property is inferred from the `neat_open` and `neat_accept` calls. Do not
set this property manually.
