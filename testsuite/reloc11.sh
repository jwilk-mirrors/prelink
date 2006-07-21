#!/bin/bash
. `dirname $0`/functions.sh
rm -f reloc11 reloc11lib*.so reloc11.log
rm -f prelink.cache
$CC -shared -O2 -nostdlib -fpic -o reloc11lib1.so $srcdir/reloc10lib4.c
$CC -shared -O2 -nostdlib -fpic -o reloc11lib2.so $srcdir/reloc11lib2.c
$CC -shared -O2 -nostdlib -fpic -o reloc11lib3.so $srcdir/reloc11lib3.c reloc11lib2.so
BINS="reloc11"
LIBS="reloc11lib1.so reloc11lib2.so reloc11lib3.so"
$CCLINK -o reloc11 $srcdir/reloc11.c -Wl,--rpath-link,. reloc11lib1.so reloc11lib3.so
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./reloc11 > reloc11.log
$PRELINK ${PRELINK_OPTS--vm} ./reloc11 >> reloc11.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` reloc11.log && exit 2
LD_LIBRARY_PATH=. ./reloc11 || exit 3
readelf -a ./reloc11 >> reloc11.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./reloc11
comparelibs >> reloc11.log 2>&1 || exit 5
