#!/bin/bash

# Options supported:
# -ut on
# -enc on
# -werror no
# -sync <posix|=std>
# -std <98|=11|17>
# -bonding on
# -testing no
# -codecov no
# -examples no
# -logging on
# -debug no


# First argument is the directory.
# If first argument is option, directory is .

OPTMATCH="-*"
if [[ "$1" == $OPTMATCH ]]; then
	DIR=.
else
	DIR=$1
	shift
fi

HERE=`dirname $0`
source $HERE/../options.sh.src

OPTIONS_STR=$(check_options "$@") ||  exit 1
eval "declare -A OPTIONS=( $OPTIONS_STR )"

CMAKE_ARGS=" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
CMAKE_ARGS+=" "-DENABLE_UNITTESTS=$(cmake_ON ${OPTIONS[-ut]})
CMAKE_ARGS+=" "-DENABLE_ENCRYPTION=$(cmake_OFF ${OPTIONS[-enc]})
CMAKE_ARGS+=" "-DCMAKE_COMPILE_WARNING_AS_ERROR=$(cmake_ON ${OPTIONS[-werror]})
CMAKE_ARGS+=" "-DENABLE_STDCXX_SYNC=$(cmake_OFF_if posix ${OPTIONS[-sync]})
CMAKE_ARGS+=" "-DUSE_CXX_STD=$(if_empty 11 ${OPTIONS[-std]})
CMAKE_ARGS+=" "-DENABLE_BONDING=$(cmake_OFF ${OPTIONS[-bonding]})
CMAKE_ARGS+=" "-DENABLE_TESTING=$(cmake_ON ${OPTIONS[-testing]})
CMAKE_ARGS+=" "-DENABLE_CODE_COVERAGE=$(cmake_ON ${OPTIONS[-codecov]})
CMAKE_ARGS+=" "-DENABLE_EXAMPLES=$(cmake_ON ${OPTIONS[-examples]})
CMAKE_ARGS+=" "-DENABLE_LOGGING=$(cmake_OFF ${OPTIONS[-logging]})
CMAKE_ARGS+=" "-DENABLE_DEBUG=$(cmake_ON ${OPTIONS[-debug]})
CMAKE_ARGS+=${OPTIONS[-extra]}

set -o xtrace

mkdir -p $DIR && cd $DIR && cmake ../ $CMAKE_ARGS

