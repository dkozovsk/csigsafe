#!/bin/bash
export LC_ALL=C

cd ./$testdir
result=$?
if [ $result -ne 0 ] 
then
    echo "cd error"
    exit 1
fi
make
result=$?
if [ $result -ne 0 ] 
then
    echo "make error"
    exit 1
fi
sed 's/:0:$/:/' test.err >test.tmp
sed 's/:0,$/,/' test.tmp >test.err
diff -u ./test.err ./test.exp
result=$?
rm -f ./test.err ./test.tmp
exit $result
