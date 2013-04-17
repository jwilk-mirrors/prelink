#!/bin/bash
. `dirname $0`/functions.sh
rm -f cxx3 cxx3lib*.so cxx3.log
rm -f prelink.cache
$CXX -shared -O2 -fpic -o cxx3lib1.so $srcdir/cxx3lib1.C
$CXX -shared -O2 -fpic -o cxx3lib2.so $srcdir/cxx3lib2.C cxx3lib1.so
BINS="cxx3"
LIBS="cxx3lib1.so cxx3lib2.so"
$CXXLINK -o cxx3 $srcdir/cxx3.C -Wl,--rpath-link,. cxx3lib2.so cxx3lib1.so
savelibs
echo $PRELINK -vvvv ${PRELINK_OPTS--vm} ./cxx3 > cxx3.log
$PRELINK -vvvv ${PRELINK_OPTS--vm} ./cxx3 >> cxx3.log 2>&1 || exit 1
grep ^`echo $PRELINK | sed 's/ .*$/: /'` cxx3.log | grep -q -v 'C++ conflict' && exit 2
[ $( grep ^`echo $PRELINK | sed 's/ .*$/: /'` cxx3.log | grep 'Removing C++ conflict' | wc -l ) -ge 29 ] || exit 3
LD_LIBRARY_PATH=. ./cxx3 || exit 4
readelf -a ./cxx3 >> cxx3.log 2>&1 || exit 5
# So that it is not prelinked again
chmod -x ./cxx3
comparelibs >> cxx3.log 2>&1 || exit 6
