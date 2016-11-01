<img src="https://cdn.rawgit.com/NEAT-project/neat/master/docs/_static/neat_logo.svg" width="350"/>

<a href="http://neat.readthedocs.io/en/latest">
    <img src="https://readthedocs.org/projects/neat/badge/?version=latest"/>
</a>

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

## Requirements :point_up:
* `cmake`
* `libuv`
* `ldns`
* `ljansson`
* `libmnl (linux only)`
* `libsctp-dev (linux only, for kernel SCTP support)`

| OS               | Install Dependencies                                                                 |
| :--------------- | :----------------------------------------------------------------------------------- |
| Debian/Ubuntu*   | `apt-get install cmake libuv1-dev libldns-dev libjansson-dev libmnl-dev libsctp-dev` |
| FreeBSD          | `pkg install cmake libuv ldns jansson`                                               |
| OS X             | `brew install cmake libuv ldns jansson`                                              |
\* Ubuntu 15.04 and higher

## Quickstart :rocket:
```shell
$ cd <path-to-neat-src>
$ mkdir build && cd build
$ cmake ..
$ cmake --build .
```
This will generate makefiles and compile the library and the samples.
You will find the shared and the static library in the `build` directory and the samples in `build/examples` directory.

For an easy introduction to NEAT, have a look at our [tutorial](http://neat.readthedocs.io/en/latest/tutorial.html).

You may also look at `neat_http_get.c` in the `samples` directory for a practical example.
```shell
$ ./client_http_get www.neat-project.org
```

In order to (optionally) install the neat library simply run.
```shell
$ sudo make install
```
Don't forget to run ldconfig after installing neat the first time.

## Read the docs :bulb:
Have a look at our [documentation](http://neat.readthedocs.io)!

## Buildbots :fire:
We are running [buildbots](http://buildbot.nplab.de:28010/waterfall) to support our continuous integration process.

If you are only interested in a single branch, just add `?branch=BRANCHNAME` to the URL. http://buildbot.nplab.de:28010/waterfall?branch=master

## Links :link:
* [www.neat-project.org](https://www.neat-project.org)
* [twitter.com/H2020Neat](https://twitter.com/H2020Neat)

## Acknowledgement
This work has received funding from the European Union's Horizon 2020 research and innovation programme under grant agreement No. 644334 (NEAT). The views expressed are solely those of the author(s).
