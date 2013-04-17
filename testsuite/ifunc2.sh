#!/bin/bash
. `dirname $0`/functions.sh
# First check if __thread is supported by ld.so/gcc/ld/as:
$CCLINK -o ifunctest $srcdir/ifunctest.c -Wl,--rpath-link,. > /dev/null 2>&1 || exit 77
( ./ifunctest || { rm -f ifunctest; exit 77; } ) 2>/dev/null || exit 77
rm -f ifunctest ifunc2 ifunc2lib*.so ifunc2.log
rm -f prelink.cache
$CC -shared -O2 -fpic -o ifunc2lib1.so $srcdir/ifunc1lib1.c -DPICKNO=2
$CC -shared -O2 -fpic -o ifunc2lib2.so $srcdir/ifunc1lib2.c ifunc2lib1.so -DPICKNO=2
BINS="ifunc2"
LIBS="ifunc2lib1.so ifunc2lib2.so"
$CCLINK -o ifunc2 $srcdir/ifunc1.c -Wl,--rpath-link,. ifunc2lib2.so -lc ifunc2lib1.so -DPICKNO=2
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./ifunc2 >> ifunc2.log
$PRELINK ${PRELINK_OPTS--vm} ./ifunc2 >> ifunc2.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` ifunc2.log && exit 2
LD_LIBRARY_PATH=. ./ifunc2 || exit 3
readelf -a ./ifunc2 >> ifunc2.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./ifunc2
comparelibs >> ifunc2.log 2>&1 || exit 5
