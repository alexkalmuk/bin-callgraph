#!/bin/sh

set -e

TEST=$1
TEST_DIR=../test

echo "Running test $TEST"

rm -f $TEST
rm -f $TEST.out
gcc -O0 -g3 $TEST_DIR/$TEST.c -o $TEST
./instr -f $TEST_DIR/$TEST.txt $TEST && chmod +x $TEST.out

echo "Run out ELF"
./$TEST.out
