#!/bin/bash
. `dirname $0`/functions.sh
rm -f shuffle5 shuffle5lib*.so shuffle5.log shuffle5.lds
rm -f prelink.cache
$CC -shared -O2 -fpic -o shuffle5lib1.so $srcdir/reloc1lib1.c
$CC -shared -O2 -fpic -o shuffle5lib2.so $srcdir/reloc1lib2.c shuffle5lib1.so
BINS="shuffle5"
LIBS="shuffle5lib1.so shuffle5lib2.so"
$CCLINK -o shuffle5 $srcdir/reloc1.c -Wl,--rpath-link,. shuffle5lib2.so -lc shuffle5lib1.so \
  -Wl,--verbose 2>&1 | sed -e '/^=========/,/^=========/!d;/^=========/d' \
  -e 's/0x08048000/0x08000000/;s/SIZEOF_HEADERS.*$/& . += 180;/' > shuffle5.lds
$CCLINK -o shuffle5 $srcdir/reloc1.c -Wl,--rpath-link,. shuffle5lib2.so -lc shuffle5lib1.so \
  -Wl,-T,shuffle5.lds
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./shuffle5 > shuffle5.log
$PRELINK ${PRELINK_OPTS--vm} ./shuffle5 >> shuffle5.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` shuffle5.log && exit 2
LD_LIBRARY_PATH=. ./shuffle5 || exit 3
readelf -a ./shuffle5 >> shuffle5.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./shuffle5
comparelibs >> shuffle5.log 2>&1 || exit 5
