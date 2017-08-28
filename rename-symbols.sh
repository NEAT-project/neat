#!/bin/sh
# Rename private neat symbols

# Functions within the neat library that are meant to be externally visible
# should be prefixed with `neat_`.

# Functions within the neat library that are global but private, not meant to be
# externally accessible, should instead be prefixed with `nt_`.

# Replace like this

# If you have older code/branches you can apply the rename yourself using this
# script. Invoke `rename-symbol.sh` in your NEAT source code tree root.
#
# Uses a for loop to work with sed commands lacking --in-place
#
# With GNU sed:
# "sed --in-place -f sed-file *.[ch] tests/neat_resolver_example.c"
#
for a in *.[ch] tests/neat_resolver_example.c; do
    echo "Fix $a"
    sed -f sed-file $a > $a.bak
    mv $a.bak $a
done
