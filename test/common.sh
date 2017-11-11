set -u

function clean_blocker {
	if [ -e $1 ]; then
		if [ -n "`cat $1`" ]; then
			echo Cleaning up $1
			kill `cat $1`
		fi
		rm $1
	fi
}

function cleanup {
	for b in blocker*.pid; do
		clean_blocker $b
	done

	if [ -e server.pid ]; then
		kill `cat server.pid`
		# The daemon deletes the PID file itself
	fi
	rm server 2> /dev/null
}

function assert {
    local ret=$?
    if [ $ret -ne $1 ]; then
	echo "Return code is not $1, but $ret"
	exit 1
    fi
}

trap cleanup EXIT

echo "Warning: tests must be run as root (CAP_SYS_ADMIN)"
