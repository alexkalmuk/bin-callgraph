#!/bin/sh

set -e

TEST=$1
INSTR_FILE=$(find ../test -type f -name $TEST.txt)

echo "Running test $TEST"

rm -f $TEST.out
./instr -f $INSTR_FILE $TEST && chmod +x $TEST.out

echo "Run out ELF"
./$TEST.out
