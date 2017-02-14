

| Property name       | Possible values   | Description | Notes |
|---------------------|-------------------|-------------|-------|
| `ip_version`        | 4 or 6            | | |    
| `local_ip`          | integer/dotted IP | | |
| `remote_ip`         | integer/dotted IP | | |
| `remote_name`       | domain name       | | |
| `transport`         | TCP, UDP, SCTP, … | | |
| `transport_ordered` | true/false        | | |
| `transport_type`    | stream/message    | | |
| `low_latency`       | true/false        | | |
| `interface`         | eth0, en1, …      | local interface  | |
| `interface_wired`   | true/false        | implies interface_wireless:false | |
| `flow_size_bytes`   | integer           | number of bytes the flow intends to transfer | |
