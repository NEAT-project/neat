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
echo 'logging to /var/log/neatpm.log'