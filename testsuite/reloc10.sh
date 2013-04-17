#!/bin/bash
. `dirname $0`/functions.sh
rm -f reloc10 reloc10lib*.so reloc10.log
rm -f prelink.cache
$CC -shared -O2 -fpic -o reloc10lib1.so $srcdir/reloc10lib1.c
$CC -shared -O2 -nostdlib -fpic -o reloc10lib2.so $srcdir/reloc10lib2.c reloc10lib1.so
$CC -shared -O2 -nostdlib -fpic -o reloc10lib3.so $srcdir/reloc10lib3.c reloc10lib1.so
$CC -shared -O2 -nostdlib -fpic -o reloc10lib4.so $srcdir/reloc10lib4.c reloc10lib1.so
$CC -shared -O2 -fpic -o reloc10lib5.so $srcdir/reloc10lib5.c -Wl,--rpath-link,. \
  reloc10lib2.so reloc10lib3.so reloc10lib4.so
BINS="reloc10"
LIBS="reloc10lib1.so reloc10lib2.so reloc10lib3.so reloc10lib4.so reloc10lib5.so"
$CCLINK -o reloc10 $srcdir/reloc10.c -Wl,--rpath-link,. reloc10lib5.so -lc reloc10lib{2,3,4}.so
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./reloc10 > reloc10.log
$PRELINK ${PRELINK_OPTS--vm} ./reloc10 >> reloc10.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` reloc10.log && exit 2
LD_LIBRARY_PATH=. ./reloc10 || exit 3
readelf -a ./reloc10 >> reloc10.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./reloc10
comparelibs >> reloc10.log 2>&1 || exit 5
