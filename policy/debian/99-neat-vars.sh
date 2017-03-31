#!/bin/sh

# This script may be placed in /etc/profile.d to globally export the
# NEAT Policy manager domain socket directory.

SOCKDIR="/var/run/neat"
export NEAT_PM_SOCKET=$SOCKDIR/neat_pm_socket
export NEAT_CIB_SOCKET=$SOCKDIR/neat_cib_socket
export NEAT_PIB_SOCKET=$SOCKDIR/neat_pib_socket
