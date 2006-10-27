#!/bin/bash
. `dirname $0`/functions.sh
# This test takes a lot of time, so skip it normally
[ -z "$CHECK_ME_HARDER" ] && exit 77
rm -f reloc4 reloc4lib*.so reloc4.log
rm -f prelink.cache
$CC -O2 -o reloc4lib1.tmp $srcdir/reloc4lib1.c
$CC -O2 -o reloc4lib2.tmp $srcdir/reloc4lib2.c
$CC -O2 -o reloc4lib3.tmp $srcdir/reloc4lib3.c
$CC -O2 -o reloc4.tmp $srcdir/reloc4.c
./reloc4lib1.tmp > reloc4lib1.tmp.c
./reloc4lib2.tmp > reloc4lib2.tmp.c
./reloc4lib3.tmp > reloc4lib3.tmp.c
./reloc4.tmp > reloc4.tmp.c
case "`$RUN uname -m`" in
  mips*) extra=-mxgot ;;
  *) extra= ;;
esac
$CC -shared -fpic $extra -o reloc4lib1.so reloc4lib1.tmp.c
$CC -shared -fpic $extra -o reloc4lib2.so reloc4lib2.tmp.c reloc4lib1.so
$CC -shared -fpic $extra -o reloc4lib3.so reloc4lib3.tmp.c reloc4lib2.so
BINS="reloc4"
LIBS="reloc4lib1.so reloc4lib2.so reloc4lib3.so"
$CCLINK $extra -o reloc4 reloc4.tmp.c -Wl,--rpath-link,. reloc4lib3.so
savelibs
rm -f reloc4*.tmp reloc4*.tmp.c
echo $PRELINK ${PRELINK_OPTS--vm} ./reloc4 > reloc4.log
$PRELINK ${PRELINK_OPTS--vm} ./reloc4 >> reloc4.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` reloc4.log && exit 2
LD_LIBRARY_PATH=. ./reloc4 || exit 3
readelf -a ./reloc4 >> reloc4.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./reloc4
comparelibs >> reloc4.log 2>&1 || exit 5
