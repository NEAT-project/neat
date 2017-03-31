#!/bin/sh

# This script may be placed in /etc/profile.d to globally export the
# NEAT Policy manager domain socket directory.

SOCKDIR="/var/run/neat"
export NEAT_PM_SOCKET=$SOCKDIR/neat_pm_socket
