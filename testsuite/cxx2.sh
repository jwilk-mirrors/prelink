#!/bin/bash
. `dirname $0`/functions.sh
rm -f cxx2 cxx2lib*.so cxx2.log
rm -f prelink.cache
$CXX -shared -O2 -fpic -o cxx2lib1.so $srcdir/cxx1lib1.C
$CXX -shared -O2 -fpic -o cxx2lib2.so $srcdir/cxx1lib2.C cxx2lib1.so
BINS="cxx2"
LIBS="cxx2lib1.so cxx2lib2.so"
$CXXLINK -o cxx2 $srcdir/cxx2.C -Wl,--rpath-link,. cxx2lib2.so
savelibs
echo $PRELINK -vvvv ${PRELINK_OPTS--vm} ./cxx2 > cxx2.log
$PRELINK -vvvv ${PRELINK_OPTS--vm} ./cxx2 >> cxx2.log 2>&1 || exit 1
grep ^`echo $PRELINK | sed 's/ .*$/: /'` cxx2.log | grep -q -v 'C++ conflict' && exit 2
[ $( grep ^`echo $PRELINK | sed 's/ .*$/: /'` cxx2.log | grep 'Removing C++ conflict' | wc -l ) -ge 9 ] || exit 3
LD_LIBRARY_PATH=. ./cxx2 || exit 4
readelf -a ./cxx2 >> cxx2.log 2>&1 || exit 5
# So that it is not prelinked again
chmod -x ./cxx2
comparelibs >> cxx2.log 2>&1 || exit 6
