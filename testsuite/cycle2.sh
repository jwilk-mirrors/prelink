#!/bin/bash
. `dirname $0`/functions.sh
rm -f cycle2 cycle2lib*.so cycle2.log
rm -f prelink.cache
# Test whether prelink doesn't segfault or loop endlessly on
# bogus library dependency chains
echo 'int i1;' | $CC -shared -O2 -fpic -o cycle2lib1.so -xc -
echo 'int i2;' | $CC -shared -O2 -fpic -o cycle2lib2.so -xc - -xnone cycle2lib1.so
echo 'int i3;' | $CC -shared -O2 -fpic -o cycle2lib3.so -xc - -xnone cycle2lib2.so
echo 'int i4;' | $CC -shared -O2 -fpic -o cycle2lib4.so -xc - -xnone cycle2lib3.so
echo 'int i5;' | $CC -shared -O2 -fpic -o cycle2lib5.so -xc - -xnone cycle2lib4.so
echo 'int i1;' | $CC -shared -O2 -fpic -o cycle2lib1.so -xc - -xnone cycle2lib5.so
BINS="cycle2"
LIBS="cycle2lib1.so cycle2lib2.so cycle2lib3.so cycle2lib4.so cycle2lib5.so"
echo 'int main (void) { return 0; } ' \
  | $CCLINK -o cycle2 -xc - -xnone -Wl,--rpath-link,. cycle2lib5.so
savelibs
echo $PRELINK ${PRELINK_OPTS--vm} ./cycle2 > cycle2.log
$PRELINK ${PRELINK_OPTS--vm} ./cycle2 >> cycle2.log 2>&1 || exit 1
grep -v 'has a dependency cycle' cycle2.log \
  | grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` && exit 2
grep -q "^`echo $PRELINK | sed 's/ .*$/: .*has a dependency cycle/'`" \
  cycle2.log || exit 3
LD_LIBRARY_PATH=. ./cycle2 || exit 4
# So that it is not prelinked again
chmod -x ./cycle2
