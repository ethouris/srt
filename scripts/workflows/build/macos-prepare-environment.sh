#!/bin/bash

HERE=`dirname $0`
source $HERE/../options.sh.src

OPTIONS_STR=$(check_options "$@") || exit 1
eval "declare -A OPTIONS=( $OPTIONS_STR )"

set -o xtrace
if is_enable ${OPTIONS[-ut]}; then WITH_UT=1; fi

echo brew install make cmake llvm

if (( $WITH_UT )); then
	brew tap-new Haivision/gt-local
	brew extract --version=1.12.1 --force googletest Haivision/gt-local
	brew trust Haivision/gt-local
	brew install googletest@1.12.1
	# NOTE: 1.12.1 is the last version that requires C++11; might need update later
	# curl -o googletest.rb https://raw.githubusercontent.com/Homebrew/homebrew-core/23e7fb4dc0cc73facc3772815741e1deb87d6406/Formula/googletest.rb
	# brew install -s googletest.rb
fi
