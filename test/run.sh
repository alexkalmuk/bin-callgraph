#!/bin/bash

PROJECT_ROOT=../
LOG=run.log

find_str () {
	cat run.log | grep "$1" &> /dev/null

	if [ $? -ne 0 ]; then
		echo "Error matching pattern: $1"
		exit 1
	fi
}

rm -f $LOG
$PROJECT_ROOT/test/test.sh test/single_func_modify_ecx | tee $LOG
find_str "dst = 0x00000000"
find_str "Run out ELF"
find_str "dst = 0x12345678"

echo -e "\n"
rm -f $LOG
$PROJECT_ROOT/test/test.sh test/c++_single_func_modify_ecx | tee $LOG
find_str "dst = 0x00000000"
find_str "Run out ELF"
find_str "dst = 0x12345678"

echo -e "\n"
rm -f $LOG
$PROJECT_ROOT/test/test.sh test/multi_func_modify_ecx | tee $LOG
find_str "dst1 = 0x00000000"
find_str "dst2 = 0x00000000"
find_str "Run out ELF"
find_str "dst1 = 0x12345678"
find_str "dst2 = 0x87654321"

echo -e "\n"
rm -f $LOG
$PROJECT_ROOT/test/test.sh test/multi_func_static_lib_modify_ecx | tee $LOG
find_str "dst1 = 0x00000000"
find_str "dst2 = 0x00000000"
find_str "Run out ELF"
find_str "dst1 = 0x12345678"
find_str "dst2 = 0x87654321"
