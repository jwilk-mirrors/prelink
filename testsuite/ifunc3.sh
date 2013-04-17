#!/bin/bash
. `dirname $0`/functions.sh
# First check if __thread is supported by ld.so/gcc/ld/as:
$CCLINK -o ifunctest $srcdir/ifunctest.c -Wl,--rpath-link,. > /dev/null 2>&1 || exit 77
( ./ifunctest || { rm -f ifunctest; exit 77; } ) 2>/dev/null || exit 77
rm -f ifunctest ifunc3 ifunc3lib*.so ifunc3.log
rm -f prelink.cache
$CC -shared -O2 -fpic -o ifunc3lib1.so $srcdir/ifunc3lib1.c
$CC -shared -O2 -fpic -o ifunc3lib2.so $srcdir/ifunc1lib2.c ifunc3lib1.so
BINS="ifunc3"
LIBS="ifunc3lib1.so ifunc3lib2.so"
$CCLINK -o ifunc3 $srcdir/ifunc3.c -Wl,--rpath-link,. ifunc3lib2.so -lc ifunc3lib1.so
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./ifunc3 >> ifunc3.log
$PRELINK ${PRELINK_OPTS--vm} ./ifunc3 >> ifunc3.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` ifunc3.log && exit 2
LD_LIBRARY_PATH=. ./ifunc3 || exit 3
readelf -a ./ifunc3 >> ifunc3.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./ifunc3
comparelibs >> ifunc3.log 2>&1 || exit 5
