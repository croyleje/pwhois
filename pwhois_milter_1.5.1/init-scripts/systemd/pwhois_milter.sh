#!/usr/bin/env bash
d="/var/run/pwhois_milter.pid"
w="/var/run/pwhois_milter_sh.pid"
f="/var/log/pwhois_milter.log"
u=512
g=512
t=3356

rmpid() {
	local f p
	f="$1"
	[[ -f "$f" ]] && p="`< "$f"`" || p=""
	[[ "$p" ]] && kill "$p"
}

sigfn() {
	[[ "$p" ]] && kill "$p"
	rm -f "$w" "$d"
	exit
}
trap sigfn SIGTERM SIGINT SIGQUIT SIGHUP

rmpid "$d"
rmpid "$w"
echo "$$" > "$w"

while true
do
	touch "$f"
	chown "$u":"$g" "$f"
	chmod 0600 "$f"
#	run in foreground = -f
	/usr/local/sbin/pwhois_milter -i "$d" -l "$f" -u "$u" -g "$g" -s 'inet:'"$t"'@localhost' -f & p="$!"
#	echo "$p" > "$d"
	wait
	p=""
	rm "$d"
	sleep 1
done

# EOF
