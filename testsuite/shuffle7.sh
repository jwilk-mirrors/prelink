#!/bin/bash
. `dirname $0`/functions.sh
rm -f shuffle7 shuffle7lib*.so shuffle7.log shuffle7.lds
rm -f prelink.cache
$CC -shared -O2 -fpic -o shuffle7lib1.so $srcdir/reloc1lib1.c
$CC -shared -O2 -fpic -o shuffle7lib2.so $srcdir/reloc1lib2.c shuffle7lib1.so
BINS="shuffle7"
LIBS="shuffle7lib1.so shuffle7lib2.so"
$CCLINK -o shuffle7 $srcdir/reloc1.c -Wl,--rpath-link,. shuffle7lib2.so \
  -Wl,--verbose 2>&1 | sed -e '/^=========/,/^=========/!d;/^=========/d' \
  -e '/\.hash/a\
  . = . + 0x300;' > shuffle7.lds
$CCLINK -o shuffle7 $srcdir/reloc1.c -Wl,--rpath-link,. shuffle7lib2.so \
  -Wl,-T,shuffle7.lds
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./shuffle7 > shuffle7.log
$PRELINK ${PRELINK_OPTS--vm} ./shuffle7 >> shuffle7.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` shuffle7.log && exit 2
LD_LIBRARY_PATH=. ./shuffle7 || exit 3
readelf -a ./shuffle7 >> shuffle7.log 2>&1 || exit 4
comparelibs >> shuffle7.log 2>&1 || exit 5
for l in shuffle7lib{1,2}.so{,.orig}; do mv -f $l $l.first; done
cp -p shuffle7 shuffle7.first
$CC -shared -O2 -fpic -o shuffle7lib1.so $srcdir/shuffle6lib1.c
$CC -shared -O2 -fpic -o shuffle7lib2.so $srcdir/shuffle6lib2.c shuffle7lib1.so
for l in shuffle7lib{1,2}.so; do cp -p $l $l.orig; done
echo $PRELINK ${PRELINK_OPTS--vm} ./shuffle7 >> shuffle7.log
$PRELINK ${PRELINK_OPTS--vm} ./shuffle7 >> shuffle7.log 2>&1 || exit 6
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` shuffle7.log && exit 7
LD_LIBRARY_PATH=. ./shuffle7 || exit 8
readelf -a ./shuffle7 >> shuffle7.log 2>&1 || exit 9
comparelibs >> shuffle7.log 2>&1 || exit 10
for l in shuffle7lib{1,2}.so{,.orig}; do mv -f $l $l.second; done
cp -p shuffle7 shuffle7.second
for l in shuffle7lib{1,2}.so{,.orig}; do cp -p $l.first $l; done
echo $PRELINK ${PRELINK_OPTS--vm} ./shuffle7 >> shuffle7.log
$PRELINK ${PRELINK_OPTS--vm} ./shuffle7 >> shuffle7.log 2>&1 || exit 11
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` shuffle7.log && exit 12
LD_LIBRARY_PATH=. ./shuffle7 || exit 13
readelf -a ./shuffle7 >> shuffle7.log 2>&1 || exit 14
comparelibs >> shuffle7.log 2>&1 || exit 15
cmp -s shuffle7{,.first} || exit 16
# So that it is not prelinked again
chmod -x ./shuffle7
