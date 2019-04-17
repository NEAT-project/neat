
# Policy Manager
## Requirements
**Note**: Developed and tested on Ubuntu 18.04 64-bit and Debian GNU/Linux 9,
* `ljansson`
* `libuv`
* `libulfius-dev`
* `libmicrohttpd-dev`

### Install requirements
##### Packages
| Prerequisite        | Install command           | 
| ------------- |:-------------:|
| If you **already have** the NEAT dependencies | `apt-get install libmicrohttpd-dev libulfius-dev` |
| If you **don't have** the NEAT dependencies. | `apt-get install cmake libjansson-dev libuv1-dev libmicrohttpd-dev libulfius-dev` |

## Quick Start

Start with copying your **PIB files** to the backend folder:

```
$ mkdir -p ~/.neat/pib/profile
$ mkdir -p ~/.neat/pib/policy
$ cp policy_manager/json_examples/pib/*.profile ~/.neat/pib/profile
$ cp policy_manager/json_examples/pib/*.policy ~/.neat/pib/policy
```

To **build & run** the policy manager, run:

```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ ./neatpmd
```

## Install as a daemon

To install the policy manager as a daemon:

```
$ sudo make install
```

This will install the policy manager in /usr/local/bin and create a new systemd service **neat_pm.service**.

To start the policy manager:

```
$ sudo systemctl start neat_pm
```

PM will now run as a background service.

To have the PM start at system boot run

```
$ sudo systemctl enable neat_pm
```
