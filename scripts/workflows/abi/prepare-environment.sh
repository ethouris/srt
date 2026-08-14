#!/bin/bash

if [[ "`id -u`" != "0" ]]; then
	echo "REQUIRED ROOT; attempting to resolve into sudo:"
	exec sudo $0 "$@"
fi

# Check distro
eval `cat /etc/*release* | grep ^NAME`

echo "System detected: $NAME"

case "$NAME" in
	Ubuntu)
		apt install -y abi-dumper abi-compliance-checker tcl
		;;

	openSUSE*)
		zypper install -y abi-dumper abi-compliance-checker tcl
		;;

	*)
		echo >&2 "ERROR: Unsupported system. Please update script"
		exit 1
		;;
esac


