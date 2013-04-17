#!/bin/bash
. `dirname $0`/functions.sh
# First check if __thread is supported by ld.so/gcc/ld/as:
rm -f tlstest
echo '__thread int a; int main (void) { return a; }' \
  | $CC -xc - -o tlstest > /dev/null 2>&1 || exit 77
( ./tlstest || { rm -f tlstest; exit 77; } ) 2>/dev/null || exit 77
rm -f tls6 tls6lib*.so tls6.log
rm -f prelink.cache
echo 'int tls6;' | $CC -shared -O2 -fpic -xc - -o tls6lib3.so
$CC -shared -O2 -fpic -o tls6lib1.so $srcdir/tls6lib1.c tls6lib3.so
$CC -shared -O2 -fpic -o tls6lib2.so $srcdir/tls1lib2.c \
  -Wl,--rpath-link,. tls6lib1.so
BINS="tls6"
LIBS="tls6lib1.so tls6lib2.so tls6lib3.so"
$CCLINK -o tls6 $srcdir/tls2.c -Wl,--rpath-link,. tls6lib2.so -lc tls6lib1.so
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./tls6 > tls6.log
$PRELINK ${PRELINK_OPTS--vm} ./tls6 >> tls6.log 2>&1 || exit 1
grep -v 'has undefined non-weak symbols' tls6.log \
  | grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` && exit 2
LD_LIBRARY_PATH=. ./tls6 || exit 3
$PRELINK -u tls6lib3.so || exit 4
echo $PRELINK ${PRELINK_OPTS--vm} ./tls6 >> tls6.log
$PRELINK ${PRELINK_OPTS--vm} ./tls6 >> tls6.log 2>&1 || exit 5
grep -v 'has undefined non-weak symbols' tls6.log \
  | grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` && exit 6
LD_LIBRARY_PATH=. ./tls6 || exit 7
readelf -a ./tls6 >> tls6.log 2>&1 || exit 8
# So that it is not prelinked again
chmod -x ./tls6
comparelibs >> tls6.log 2>&1 || exit 9
