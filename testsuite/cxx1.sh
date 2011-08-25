#!/bin/bash
. `dirname $0`/functions.sh
rm -f cxx1 cxx1lib*.so cxx1.log
rm -f prelink.cache
$CXX -shared -O2 -fpic -o cxx1lib1.so $srcdir/cxx1lib1.C
$CXX -shared -O2 -fpic -o cxx1lib2.so $srcdir/cxx1lib2.C cxx1lib1.so
BINS="cxx1"
LIBS="cxx1lib1.so cxx1lib2.so"
$CXXLINK -o cxx1 $srcdir/cxx1.C -Wl,--rpath-link,. cxx1lib2.so
savelibs
echo $PRELINK -vvvv ${PRELINK_OPTS--vm} ./cxx1 > cxx1.log
$PRELINK -vvvv ${PRELINK_OPTS--vm} ./cxx1 >> cxx1.log 2>&1 || exit 1
grep ^`echo $PRELINK | sed 's/ .*$/: /'` cxx1.log | grep -q -v 'C++ conflict' && exit 2
case "`uname -m`" in
  arm*) ;; # EABI says that vtables/typeinfo aren't vague linkage if there is a key method
  *) [ $( grep ^`echo $PRELINK | sed 's/ .*$/: /'` cxx1.log | grep 'Removing C++ conflict' | wc -l ) -ge 5 ] || exit 3;;
esac
LD_LIBRARY_PATH=. ./cxx1 || exit 4
readelf -a ./cxx1 >> cxx1.log 2>&1 || exit 5
# So that it is not prelinked again
chmod -x ./cxx1
comparelibs >> cxx1.log 2>&1 || exit 6
