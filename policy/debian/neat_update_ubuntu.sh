#!/bin/sh

NEAT_DIR=~/neat

mkdir -p $NEAT_DIR/build
cd $NEAT_DIR
git pull
cd $NEAT_DIR/build
cmake ..
cmake --build .
sudo make install

sudo cp -v $NEAT_DIR/policy/debian/99-neat-vars.sh /etc/profile.d/
sudo chmod +x /etc/profile.d/99-neat-vars.sh
sudo cp -v $NEAT_DIR/policy/debian/neat-motd.sh /etc/update-motd.d/01-neat
sudo chmod +x /etc/update-motd.d/01-neat
sudo cp -v $NEAT_DIR/policy/examples/pib/* /etc/neat/pib/

sudo service neatpmd restart
/etc/init.d/neatpmd status

sudo systemctl enable neat_http_server
mkdir -p $NEAT_DIR/htdocs

sudo cp $NEAT_DIR/policy/debian/services/neat_http_server.service /lib/systemd/system


