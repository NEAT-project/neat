# NEAT
**A New, Evolutive API and Transport-Layer Architecture for the Internet**

NEAT supports **FreeBSD**, **Linux**, **OS X** and **NetBSD**


## NEAT internals :nut_and_bolt:

NEAT is a callback based library and everything revovles around the neat_ctx
struct. This struct has to be initialized before anything else can be done. NEAT
uses libuv as event library, and this loop is available to users so that they
can hook in and add their own callbacks.

One of the first things done in NEAT after the library has been initialized is
to start monitoring the available addresses on all interfaces of the machine.
NEAT supports multi-homing and we must therefore have an up-to-date view of the
available (and connected) network resources available on a machine. Address
events are published using an internal event API, which users also can hook
into. It is useful if only a small subset of NEAT is wanted, for example
monitoring the preferred lifetime of a v6 address. Look at neat_resolver.c for
an example on how to use this API. An address is stored in a
platform-independent structure.

After NEAT has been initialized, it is up to the user to do what he or she
wants. A typical first step is to resolve a domain name.

## Getting started :muscle:
### Requirements
* `cmake`
* `libuv`
* `ldns`
* `libmnl (linux only)`

| OS        | command           | 
| ------------- |:-------------| 
| Ubuntu*      | `apt-get install cmake libuv1-dev libldns-dev libmnl-dev` | 
| FreeBSD      | `pkg install cmake ldns libuv`     |   
| OS X | `brew install libuv ldns`      |   

*Older ubuntu might have a ppa for libuv1 https://launchpad.net/~cz.nic-labs/+archive/ubuntu/knot-dns

### Build NEAT and samples
```
$ cd build
$ cmake ..
$ make
```
This will generate makefiles and compile the library and the samples.
You will find the shared and the static library in the `build` directory and the samples in `build/samples` directory.

In order to install:
```
$ sudo make install
```
Don't forget to run ldconfig after installing neat the first time.

### Debug ouput :page_with_curl:
Neat offers a flexible way to control debug output via eviroment variables. 

| variable        | default           | supported values |
| :-------------  |:-------------| :------------- |
| `NEAT_LOG_LEVEL` | `NEAT_LOG_INFO` | `NEAT_LOG_OFF`, `NEAT_LOG_ERROR`, `NEAT_LOG_WARNING`, `NEAT_LOG_INFO`, `NEAT_LOG_DEBUG`
| `NEAT_LOG_FILE`  | undefined (stderr)     | filename, e.g. "neat.log"

### TODO
- [ ] Give user control of how loop is run so that it for example can be integrated into other event loops.
- [ ] Monitor more stuff, like routes?
- [x] Implement some form of logging/verbose mode. This is something that we should all agree on.
- [ ] Find a platform-independent alternative to ldns.

## Buildbots :fire:
The [buildbots](http://buildbot.nplab.de:28010/waterfall) are triggered by every commit in every branch. 

If you are only interested in a single branch, just add `?branch=BRANCHNAME` to the URL. http://buildbot.nplab.de:28010/waterfall?branch=master

## NEAT DNS resolver

NEAT contains an asynchronous multi-prefix DNS resolver. DNS requests for the
given domain will be sent to four public DNS servers on every available
interface (address). It is possible to limit query to only v4 or v6 addresses,
and a v4 interface is only used to request A records while v6 is only used to
request AAAA records.

In case of DNS poisoning or similar, the resolved address is compared agains the
well-known internal IPs (ULA or IANA A/B/C). An internal IP is flagged and it is
(so far) up to the user of NEAT to know if it is safe or not to use this IP.

The best way to look at how to use the resolver is to look at the example file,
`neat_resolver_example.c`

### TODO
- [ ] Read DNS-servers from resolv.conf. This requires us to decide on a generic way
  for specifying with interface/IP a server belongs to.
- [ ] Make resolver work on other OS' than Linux.
- [ ] Make it optional (as much as possible) if resolver should use stack or heap.
- [ ] Design a better algorithm for choosing servers, prioritizing servers sent to
  user.
- [ ] Lots of other stuff that I can't think of now.

## Acknowledgement

This work has received funding from the European Union's Horizon 2020 research and innovation programme under grant agreement No. 644334 (NEAT). The views expressed are solely those of the author(s).
