#!/bin/bash
. `dirname $0`/functions.sh
# Kernels before 2.4.10 are known not to work
case "`uname -r`" in
  [01].*|2.[0-3].*|2.4.[0-9]|2.4.[0-9][^0-9]*) exit 77;;
esac
rm -f shuffle4 shuffle4.log
BINS="shuffle4"
$CCLINK -o shuffle4 $srcdir/shuffle2.c -Wl,--rpath-link,. shuffle3lib2.so -lc shuffle3lib1.so 
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./shuffle4 > shuffle4.log
$PRELINK ${PRELINK_OPTS--vm} ./shuffle4 >> shuffle4.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` shuffle4.log && exit 2
LD_LIBRARY_PATH=. ./shuffle4 || exit 3
readelf -a ./shuffle4 >> shuffle4.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./shuffle4
comparelibs >> shuffle4.log 2>&1 || exit 5
