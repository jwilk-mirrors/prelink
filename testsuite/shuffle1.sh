#!/bin/bash
. `dirname $0`/functions.sh
rm -f shuffle1 shuffle1lib*.so shuffle1.log shuffle1.lds
rm -f prelink.cache
$CC -shared -O2 -fpic -o shuffle1lib1.so $srcdir/reloc1lib1.c
$CC -shared -O2 -fpic -o shuffle1lib2.so $srcdir/reloc1lib2.c shuffle1lib1.so
BINS="shuffle1"
LIBS="shuffle1lib1.so shuffle1lib2.so"
$CCLINK -o shuffle1 $srcdir/reloc1.c -Wl,--rpath-link,. shuffle1lib2.so -lc shuffle1lib1.so \
  -Wl,--verbose 2>&1 | sed -e '/^=========/,/^=========/!d;/^=========/d' \
  -e 's/0x08048000/0x08000000/;s/SIZEOF_HEADERS.*$/& . += 56;/' > shuffle1.lds
$CCLINK -o shuffle1 $srcdir/reloc1.c -Wl,--rpath-link,. shuffle1lib2.so -lc shuffle1lib1.so \
  -Wl,-T,shuffle1.lds
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./shuffle1 > shuffle1.log
$PRELINK ${PRELINK_OPTS--vm} ./shuffle1 >> shuffle1.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` shuffle1.log && exit 2
LD_LIBRARY_PATH=. ./shuffle1 || exit 3
readelf -a ./shuffle1 >> shuffle1.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./shuffle1
comparelibs >> shuffle1.log 2>&1 || exit 5
