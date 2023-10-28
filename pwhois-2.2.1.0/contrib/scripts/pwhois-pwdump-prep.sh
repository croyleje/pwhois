#!/bin/sh
PWDIR=/var/pwhois
RELOAD=0
PWDUMP=/usr/local/sbin/pwhois-pwdump
dumps='acl asn geo net org poc rou'
dumpcmds='-a -g -n -o -p -s -t'

# Parse command line parameters
while [ $# -gt 0 ]
do
    case "$1" in
        -r)  RELOAD=1;;
        -*)
            echo >&2 "usage: $0 [-r]"
            exit 1;;
        *)  break;;     # terminate while loop
    esac
    shift
done

cd $PWDIR

for d in $dumpcmds; do
	$PWDUMP $d || exit 1;
done

for d in $dumps; do
	if [ -f "$PWDIR/$d.pwdump.tmp" ]; then
		if [ -f "$PWDIR/$d.pwdump" ]; then
			mv ${d}.pwdump $PWDIR/${d}.pwdump.bak
		fi
		mv ${d}.pwdump.tmp  $PWDIR/$d.pwdump 
	fi
done

# Reload import latest data using pwhois-updatedb if user wants
# and if file size is nonzero 
if [ $RELOAD -gt 0 ]; then
echo "Reloading pwhoisd";

	PID=`cat /var/run/pwhoisd.pid`

	if [ $PID -gt 0 ]; then
		kill -HUP $PID
	else
		echo "ERROR: No pid file found!"	
	fi

fi
