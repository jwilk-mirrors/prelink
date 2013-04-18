#!/bin/bash
. `dirname $0`/functions.sh
# This test takes a lot of time, so skip it normally
[ -z "$CHECK_ME_HARDER" ] && exit 77
rm -f reloc5 reloc5.log
rm -f prelink.cache
$CC -O2 -o reloc5.tmp $srcdir/reloc5.c
./reloc5.tmp > reloc5.tmp.c
BINS="reloc5"
$CCLINK -o reloc5 reloc5.tmp.c -Wl,--rpath-link,. reloc4lib3.so -lc reloc4lib2.so
savelibs
rm -f reloc5*.tmp reloc5*.tmp.c
echo $PRELINK ${PRELINK_OPTS--vm} ./reloc5 > reloc5.log
$PRELINK ${PRELINK_OPTS--vm} ./reloc5 >> reloc5.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` reloc5.log && exit 2
LD_LIBRARY_PATH=. ./reloc5 || exit 3
readelf -a ./reloc5 >> reloc5.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./reloc5
comparelibs >> reloc5.log 2>&1 || exit 5
