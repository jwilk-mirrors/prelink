#!/bin/bash
. `dirname $0`/functions.sh
rm -f reloc7 reloc7lib*.so reloc7.log
rm -f prelink.cache
$CC -shared -O2 -Wl,-z,nocombreloc -fpic -o reloc7lib1.so $srcdir/reloc3lib1.c
$CC -shared -O2 -Wl,-z,nocombreloc -fpic -o reloc7lib2.so $srcdir/reloc1lib2.c reloc7lib1.so
BINS="reloc7"
LIBS="reloc7lib1.so reloc7lib2.so"
$CCLINK -o reloc7 -Wl,-z,nocombreloc $srcdir/reloc7.c -Wl,--rpath-link,. reloc7lib2.so -lc reloc7lib1.so
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./reloc7 > reloc7.log
$PRELINK ${PRELINK_OPTS--vm} ./reloc7 >> reloc7.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` reloc7.log && exit 2
LD_LIBRARY_PATH=. ./reloc7 >> reloc7.log || exit 3
readelf -a ./reloc7 >> reloc7.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./reloc7
comparelibs >> reloc7.log 2>&1 || exit 5
