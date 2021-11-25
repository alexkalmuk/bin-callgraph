#!/bin/sh

set -e

# export LD_LIBRARY_PATH=$PWD/out:LD_LIBRARY_PATH

export LD_LIBRARY_PATH=

TEST=$(basename $1)
INSTR_FILE=$(find ../test -type f -name $TEST.txt)

if [ -z $INSTR_FILE ]; then
	echo "No $TEST.txt found"
	exit 1
fi

mkdir -p out
rm -f out/*\.so
rm -f $TEST.libs
rm -f out/$TEST

ldd test/$TEST | \
	grep -vE "(linux-vdso|ld-linux|libc|libgcc|libm|libstdc++).*\.so" | \
	awk '{ print $3}' | tee $TEST.libs

echo "Running test $TEST"

./instr -f $INSTR_FILE test/$TEST && chmod +x out/$TEST
if [ $? -ne 0 ]; then
	echo "./instr failed"
	exit 1
fi

export LD_LIBRARY_PATH=$PWD/out:$LD_LIBRARY_PATH
echo "Run out ELF"
./out/$TEST
