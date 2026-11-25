#!/bin/sh
# usage: addedtests.sh <commit> [pattern]  -> names of test fns added (+) and removed (-) in the commit
cd "$(git rev-parse --show-toplevel)" || exit 1
git show --format= -U0 "$1" -- '*.rs' | awk '
  /^\+\+\+ / { file=$2; next }
  /^[+-][ \t]*#\[(test|rstest|tokio::test)/ { pend=substr($0,1,1); next }
  pend!="" && /^[+-][ \t]*(pub )?(async )?fn / { s=$0; sub(/^[+-][ \t]*(pub )?(async )?fn /,"",s); sub(/\(.*/,"",s); print pend " " s " " file; pend=""; next }
  /^[+-][ \t]*proptest!/ { print substr($0,1,1) " proptest-block " file }
' | sort | uniq
