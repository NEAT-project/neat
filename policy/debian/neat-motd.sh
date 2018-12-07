#!/bin/sh

echo '                                                                     @@@@@     '
echo '                                                                     @@@@@     '
echo '*@@@@@@@@@@@@             @@@@@@@@@            @@@@@@@@@@@           @@@@@     '
echo '@@@@@@,,%@@@@@@         @@@@@# .@@@@@          @@@@@@@@@@@@@         @@@@@@@@@@'
echo '@@@@       @@@@        @@@@       @@@@                   @@@@*       @@@@@@@@@.'
echo '@@@@       @@@@       @@@@        ,@@@@                   @@@@       @@@@@     '
echo '@@@@       @@@@       @@@@      ,@@@@@@                   @@@@,      @@@@@     '
echo '@@@@       @@@@       @@@@@@@@@@@@@@,        @@@@@@@@@@@@@@@@@@      @@@@@     '
echo '@@@@       @@@@       @@@@,                  @@@@@        @@@@,      @@@@@     '
echo '@@@@       @@@@       &@@@@                   @@@@        @@@@       @@@@@     '
echo '@@@@       @@@@        @@@@@                  @@@@@      @@@@        @@@@@     '
echo '@@@@       @@@@          @@@@@@@@@@@@           @@@@@@@@@@@@          @@@@@@@  '
echo
echo
echo 'NEAT Policy Manager'
echo 'Usage: service neatpmd {start|stop|status|restart|uninstall}'
/etc/init.d/neatpmd status
echo 'Log: /var/log/neatpmd.log'
echo
echo 'NEAT http server running on port 8080. See `systemctl status neat_http_server`'

