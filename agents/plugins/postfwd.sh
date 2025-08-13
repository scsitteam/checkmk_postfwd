#!/bin/bash

CONFIG_FILE="$MK_CONFDIR/postfwd.cfg"

if [ -r "$CONFIG_FILE" ]; then

  . "$CONFIG_FILE"

fi

echo '<<<postfwd_rules:sep(0)>>>'
/usr/sbin/postfwd --file $FILE --showconfig
echo '<<<postfwd_stats:sep(0)>>>'
/usr/sbin/postfwd --port $PORT --dumpstats