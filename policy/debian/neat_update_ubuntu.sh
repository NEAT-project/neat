#!/bin/sh

mkdir -p ~/neat/build
cd ~/neat
git pull
cd ~/neat/build
cmake ..
cmake --build .
sudo make install

sudo cp -v ~/neat/policy/debian/99-neat-vars.sh /etc/profile.d/
sudo chmod +x /etc/profile.d/99-neat-vars.sh
sudo cp -v ~/neat/policy/examples/pib/* /etc/neat/pib/

sudo service neatpmd restart
/etc/init.d/neatpmd status

sudo cp /home/neat/neat/policy/debian/services/neat_http_server.service /lib/systemd/system

