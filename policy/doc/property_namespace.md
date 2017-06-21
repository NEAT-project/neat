# NEAT API Default Properties

| Property name       | Possible values    | Default | Notes |
|---------------------|--------------------|-------------|-------|
| `low_latency`       | true/false         | false | |
| `transport`         | reliable, TCP, UDP, SCTP, … | reliable | |
| `capacity_profile`  | LBE, BE, aggressive | BE | |
| `high_availabity`   | true/false | true | |
| `dscp_value` | integer | 0 | |

The properties will be expanded to concrete values using corresponding profiles (see [current defaults](https://github.com/NEAT-project/neat/tree/master/policy/examples/pib)).


## NEAT Property namespace
This is a list of known properties, to avoid ambiguity in the PM:

| Property name        | Possible values   | Description | Notes |
|----------------------|-------------------|-------------|-------|
| `ip_version`         | 4 or 6            | | |    
| `local_ip`           | integer/dotted IP | | |
| `remote_ip`          | integer/dotted IP | | |
| `remote_name`        | domain name       | | |
| `transport_ordered`  | true/false        | | |
| `transport_type`     | stream or message | | |
| `interface`          | eth0, en1, …      | local interface  | |
| `interface_wired`    | true/false        | implies interface_wireless:false | |
| `seamless_handover`  | true | | |
| `stream_count`       | 1 | | |
| `flow_size_bytes` | integer           | number of bytes the flow intends to transfer | |
| `flow_time_ms` | float | | |
| `flow_group` | integer | | |
| `flow_priority` | integer | | |





