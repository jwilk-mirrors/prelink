#!/bin/bash
. `dirname $0`/functions.sh
# Kernels before 2.4.10 are known not to work
case "`uname -r`" in
  [01].*|2.[0-3].*|2.4.[0-9]|2.4.[0-9][^0-9]*) exit 77;;
esac
rm -f shuffle3 shuffle3lib*.so shuffle3.log shuffle3.lds
rm -f prelink.cache
$CC -shared -O2 -fpic -o shuffle3lib1.so $srcdir/reloc1lib1.c
$CC -shared -O2 -fpic -o shuffle3lib2.so $srcdir/reloc1lib2.c shuffle3lib1.so
BINS="shuffle3"
LIBS="shuffle3lib1.so shuffle3lib2.so"
$CCLINK -o shuffle3 $srcdir/shuffle2.c -Wl,--rpath-link,. shuffle3lib2.so -lc shuffle3lib1.so \
  -Wl,--verbose 2>&1 | sed -e '/^=========/,/^=========/!d;/^=========/d' \
  -e 's/0x08048000/0x08000000/' > shuffle3.lds
$CCLINK -o shuffle3 $srcdir/shuffle2.c -Wl,--rpath-link,. shuffle3lib2.so -lc shuffle3lib1.so \
  -Wl,-T,shuffle3.lds
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./shuffle3 > shuffle3.log
$PRELINK ${PRELINK_OPTS--vm} ./shuffle3 >> shuffle3.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` shuffle3.log && exit 2
LD_LIBRARY_PATH=. ./shuffle3 || exit 3
readelf -a ./shuffle3 >> shuffle3.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./shuffle3
comparelibs >> shuffle3.log 2>&1 || exit 5
