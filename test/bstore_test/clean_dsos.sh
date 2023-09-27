#!/bin/bash
#
# Run this on dsos1 and dsos2 to clean up local stores

[[ "${HOSTNAME}" == dsos* ]] || {
	echo "This script is meant to run inside 'dsos1' or 'dsos2' containers."
	exit -1
}

[[ -d /store/test ]] || {
	echo "/store/test directory not found"
	exit -1
}

cd /store/test || {
	echo "Cannot change directory to '/store/test'"
	exit -1
}

echo "Killing running dsosd:"
pgrep -a dsosd
pkill dsosd

echo "Removing existing containers in /store/test/"
rm -rf /store/test/*/

echo "Starting dsosd .."
# start rpcbind if it is not running
pgrep rpcbind 1>/dev/null 2>&1 || {
	rpcbind
	sleep 1
}
dsosd >/var/log/dsosd.log 2>&1 &
sleep 1

echo "running dsosd:"
pgrep -a dsosd
