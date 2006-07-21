#!/bin/bash
. `dirname $0`/functions.sh
rm -f shuffle8 shuffle8lib*.so shuffle8.log shuffle8.lds
rm -f prelink.cache
$CC -shared -O2 -fpic -o shuffle8lib1.so $srcdir/reloc1lib1.c
$CC -shared -O2 -fpic -o shuffle8lib2.so $srcdir/reloc1lib2.c shuffle8lib1.so
BINS="shuffle8"
LIBS="shuffle8lib1.so shuffle8lib2.so"
$CCLINK -o shuffle8 $srcdir/shuffle8.c -Wl,--rpath-link,. shuffle8lib2.so
strip -R .comment shuffle8
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./shuffle8 > shuffle8.log
$PRELINK ${PRELINK_OPTS--vm} ./shuffle8 >> shuffle8.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` shuffle8.log && exit 2
LD_LIBRARY_PATH=. ./shuffle8 || exit 3
readelf -a ./shuffle8 >> shuffle8.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./shuffle8
comparelibs >> shuffle8.log 2>&1 || exit 5
