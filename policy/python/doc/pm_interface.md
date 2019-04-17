## Policy Interface (PI):
The Policy Interface exposes a set of programming function calls that NEAT components may invoke to make requests to the NEAT Policy Manager. The JSON format was selected for the Policy Interface to achieve a decoupling of the PM from the rest of the NEAT System. In fact, the PM components described in this section may become optional or may even be executed outside the host  using them in a future version of the NEAT System, e.g., for less powerful mobile devices.

The communication interface between the Policy Manager and other NEAT components is currently implemented using Unix domain sockets. The socket `neat_pm_socket` is used to receive requests from the application and serve back a list of connection candidates to the NEAT Logic. The application request is passed as a string containing a JSON object with a set of NEAT properties, as illustrated in Listing \ref{property_format}. The request should at least contain a destination DNS name and port, or a destination IP, destination port, and a local interface and IP.

Similarly the PM response contains a configurable number of candidates encoded as a JSON list, wherein each list element is a JSON object containing the properties associated with a particular candidate. The list is order by the total score of all candidate properties.

Two additional Unix sockets, `neat_pib_socket` and `neat_cib_socket`, are  available for adding new policies and CIB nodes to the PIB and CIB respectively (in addition to the filesystem interface).

Additionally the PM exposes a REST API which is intended to allow external applications, such as SDN controllers, to query the contents of the PIB/CIB and to populate these with new entries. If this optional API is started, the PM starts listening for HTTP connections on a predefined port (45888 by default). Applications may then access the following addresses using HTTP's GET/PUT semantics (using JSON):



* `/pib` (GET) lists all policies installed in the host.
* `/pib/{uid}` (GET/PUT) retrieve or upload a policy with a specific Unique Identifier (UID).
* `/cib` (GET) lists all CIB nodes installed in the host.
* `/cib/{uid}` (GET/PUT) retrieve or upload a CIB node with a specific UID.
* `/cib/rows` (GET) retrieve all rows of the CIB repository.

