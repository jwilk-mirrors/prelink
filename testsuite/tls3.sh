#!/bin/bash
. `dirname $0`/functions.sh
# First check if __thread is supported by ld.so/gcc/ld/as:
rm -f tlstest
echo '__thread int a; int main (void) { return a; }' \
  | $CC -xc - -o tlstest > /dev/null 2>&1 || exit 77
( ./tlstest || { rm -f tlstest; exit 77; } ) 2>/dev/null || exit 77
SHFLAGS=
case "`uname -m`" in
  ia64|ppc*|x86_64|alpha*|s390*|mips*|arm*) SHFLAGS=-fpic;; # Does not support non-pic shared libs
esac
# Disable this test under SELinux if textrel
if test -z "$SHFLAGS" -a -x /usr/sbin/getenforce; then
  case "`/usr/sbin/getenforce 2>/dev/null`" in
    Permissive|Disabled) ;;
    *) exit 77 ;;
  esac
fi
rm -f tls3 tls3lib*.so tls3.log
rm -f prelink.cache
$CC -shared -O2 -fpic -o tls3lib1.so $srcdir/tls1lib1.c
$CC -shared -O2 $SHFLAGS -o tls3lib2.so $srcdir/tls3lib2.c \
  tls3lib1.so 2>/dev/null
BINS="tls3"
LIBS="tls3lib1.so tls3lib2.so"
$CCLINK -o tls3 $srcdir/tls1.c -Wl,--rpath-link,. tls3lib2.so -lc tls3lib1.so
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./tls3 > tls3.log
$PRELINK ${PRELINK_OPTS--vm} ./tls3 >> tls3.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` tls3.log && exit 2
LD_LIBRARY_PATH=. ./tls3 || exit 3
readelf -a ./tls3 >> tls3.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./tls3
comparelibs >> tls3.log 2>&1 || exit 5
