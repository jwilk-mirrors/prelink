#!/bin/bash
. `dirname $0`/functions.sh
# Disable this test under SELinux
if test -x /usr/sbin/getenforce; then
  case "`/usr/sbin/getenforce 2>/dev/null`" in
    Permissive|Disabled) ;;
    *) exit 77 ;;
  esac
fi
rm -f reloc9 reloc9lib*.so reloc9.log
rm -f prelink.cache
NOCOPYRELOC=-Wl,-z,nocopyreloc
case "`uname -m`" in
  x86_64|s390*|sparc*) if file reloc1lib1.so | grep -q 64-bit; then NOCOPYRELOC=; fi;;
esac
$CC -shared -O2 -Wl,-z,nocombreloc -fpic -o reloc9lib1.so $srcdir/reloc3lib1.c
$CC -shared -O2 -Wl,-z,nocombreloc -fpic -o reloc9lib2.so $srcdir/reloc1lib2.c reloc9lib1.so
BINS="reloc9"
LIBS="reloc9lib1.so reloc9lib2.so"
$CCLINK -o reloc9 -Wl,-z,nocombreloc $NOCOPYRELOC $srcdir/reloc7.c -Wl,--rpath-link,. reloc9lib2.so
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./reloc9 > reloc9.log
$PRELINK ${PRELINK_OPTS--vm} ./reloc9 >> reloc9.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` reloc9.log && exit 2
LD_LIBRARY_PATH=. ./reloc9 >> reloc9.log || exit 3
readelf -a ./reloc9 >> reloc9.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./reloc9
comparelibs >> reloc9.log 2>&1 || exit 5
