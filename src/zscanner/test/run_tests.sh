#!/bin/sh

TESTS_DIR="./tests"
OUTS_DIR="/tmp/zscanner_tests"
TEST_BIN="../../unittests-zscanner -m 2"

mkdir -p ${OUTS_DIR}/${TESTS_DIR}
cp -r ${TESTS_DIR}/includes ${OUTS_DIR}

separation="========================================================="

echo $separation

for file in `find $TESTS_DIR -name "*.in" | sort`; do
	fileout=`echo "$file" | sed 's/.in/.out/'`
	$TEST_BIN . $file > ${OUTS_DIR}/$fileout
	sed --in-place '/FL:/d' ${OUTS_DIR}/$fileout
	echo $fileout
	diff ${OUTS_DIR}/$fileout $fileout
	echo $separation
done
