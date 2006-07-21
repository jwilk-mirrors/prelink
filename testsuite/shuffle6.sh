#!/bin/bash
. `dirname $0`/functions.sh
rm -f shuffle6 shuffle6lib*.so shuffle6.log shuffle6.lds
rm -f prelink.cache
$CC -shared -O2 -fpic -o shuffle6lib1.so $srcdir/reloc1lib1.c
$CC -shared -O2 -fpic -o shuffle6lib2.so $srcdir/reloc1lib2.c shuffle6lib1.so
BINS="shuffle6"
LIBS="shuffle6lib1.so shuffle6lib2.so"
$CCLINK -o shuffle6 $srcdir/reloc1.c -Wl,--rpath-link,. shuffle6lib2.so \
  -Wl,--verbose 2>&1 | sed -e '/^=========/,/^=========/!d;/^=========/d' \
  -e 's/0x08048000/0x08000000/;s/SIZEOF_HEADERS.*$/& . += 56;/' > shuffle6.lds
$CCLINK -o shuffle6 $srcdir/reloc1.c -Wl,--rpath-link,. shuffle6lib2.so \
  -Wl,-T,shuffle6.lds
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./shuffle6 > shuffle6.log
$PRELINK ${PRELINK_OPTS--vm} ./shuffle6 >> shuffle6.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` shuffle6.log && exit 2
LD_LIBRARY_PATH=. ./shuffle6 || exit 3
readelf -a ./shuffle6 >> shuffle6.log 2>&1 || exit 4
comparelibs >> shuffle6.log 2>&1 || exit 5
for l in shuffle6lib{1,2}.so{,.orig}; do mv -f $l $l.first; done
cp -p shuffle6 shuffle6.first
$CC -shared -O2 -fpic -o shuffle6lib1.so $srcdir/shuffle6lib1.c
$CC -shared -O2 -fpic -o shuffle6lib2.so $srcdir/shuffle6lib2.c shuffle6lib1.so
for l in shuffle6lib{1,2}.so; do cp -p $l $l.orig; done
echo $PRELINK ${PRELINK_OPTS--vm} ./shuffle6 >> shuffle6.log
$PRELINK ${PRELINK_OPTS--vm} ./shuffle6 >> shuffle6.log 2>&1 || exit 6
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` shuffle6.log && exit 7
LD_LIBRARY_PATH=. ./shuffle6 || exit 8
readelf -a ./shuffle6 >> shuffle6.log 2>&1 || exit 9
# So that it is not prelinked again
chmod -x ./shuffle6
comparelibs >> shuffle6.log 2>&1 || exit 10
