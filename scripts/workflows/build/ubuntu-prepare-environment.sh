#!/bin/bash

if [[ "`id -u`" != "0" ]]; then
	echo "REQUIRED ROOT; attempting to resolve into sudo:"
	exec sudo $0 "$@"
fi

HERE=`dirname $0`
source $HERE/../options.sh.src

OPTIONS_STR=$(check_options "$@") ||  exit 1
eval "declare -A OPTIONS=( $OPTIONS_STR )"

MAYBE_GDB=gdb
[[ "$(cmake_OFF ${OPTIONS[-gdb]})" == "OFF"]] && MAYBE_GDB=

MAYBE_SSL=libssl-dev
[[ "$(cmake_OFF ${OPTIONS[-ssl]})" == "OFF"]] && MAYBE_SSL=

apt update
apt install -y tcl cmake $MAYBE_SSL $MAYBE_GDB

