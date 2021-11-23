#!/bin/sh

set -e

TEST=$(basename $1)
INSTR_FILE=$(find ../test -type f -name $TEST.txt)

if [ -z $INSTR_FILE ]; then
	echo "No $TEST.txt found"
	exit 1
fi

echo "Running test $TEST"

rm -f $TEST.out
./instr -f $INSTR_FILE test/$TEST && chmod +x $TEST.out

echo "Run out ELF"
./$TEST.out
