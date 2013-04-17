#!/bin/bash
. `dirname $0`/functions.sh

PRELINK=`echo $PRELINK \
	 | sed -e 's, \./\(prelink\.\(cache\|conf\)\), deps1.tree/etc/\1,g' \
	       -e 's,path=\.,path=deps1.tree/lib:deps1.tree/usr/lib:deps1.tree/opt/lib,' \
	       -e 's,linker=\./,linker=deps1.tree/lib/,'`
CCLINK=`echo $CCLINK \
	| sed -e 's,linker=\./,linker=deps1.tree/lib/,'`
rm -rf deps1.tree
rm -f deps1.log
mkdir -p deps1.tree/{lib,etc,usr/lib,opt/lib,usr/bin}
$CC -shared -O2 -fpic -o deps1.tree/usr/lib/lib1.so $srcdir/deps1lib1.c
$CC -shared -O2 -fpic -o deps1.tree/opt/lib/lib1.so $srcdir/deps1lib1.c
$CC -shared -O2 -fpic -o deps1.tree/usr/lib/lib2.so $srcdir/deps1lib2.c \
    -L deps1.tree/opt/lib -Wl,-rpath,deps1.tree/opt/lib -l1
echo '' | $CC -shared -O2 -fpic -o deps1.tree/usr/lib/lib3.so -xc - -xnone \
    -L deps1.tree/usr/lib -L deps1.tree/opt/lib -Wl,-rpath,deps1.tree/usr/lib \
    -l1 -l2
for lib in `cat syslib.list`; do
  cp -p $lib.orig deps1.tree/lib/$lib
  cp -p $lib.orig deps1.tree/lib/$lib.orig
done
for lib in `cat syslnk.list`; do
  cp -dp $lib deps1.tree/lib
done
$CCLINK -o deps1.tree/usr/bin/bin1 $srcdir/deps1.c \
    -Wl,-rpath,deps1.tree/usr/lib -L deps1.tree/usr/lib -l3 -lc -l1 -l2
cat > deps1.tree/etc/prelink.conf <<EOF
deps1.tree/usr/bin
deps1.tree/lib
deps1.tree/usr/lib
deps1.tree/opt/lib
EOF
LIBS="deps1.tree/usr/lib/lib1.so deps1.tree/usr/lib/lib2.so"
LIBS="$LIBS deps1.tree/usr/lib/lib3.so deps1.tree/opt/lib/lib1.so"
LIBS="$LIBS `sed 's|^|deps1.tree/lib/|' syslib.list`"
BINS="deps1.tree/usr/bin/bin1"
savelibs
chmod 644 `ls $BINS | sed 's|$|.orig|'`
echo $PRELINK ${PRELINK_OPTS--v} -avvvvv > deps1.log
$PRELINK ${PRELINK_OPTS--v} -avvvvv > deps1.tree/etc/log1 2>&1 || exit 1
cat deps1.tree/etc/log1 >> deps1.log
LD_LIBRARY_PATH=deps1.tree/lib deps1.tree/usr/bin/bin1 || exit 2
readelf -d deps1.tree/{usr,opt}/lib/lib1.so 2>&1 | grep CHECKSUM >> deps1.log || exit 3
readelf -A deps1.tree/usr/lib/lib1.so >> deps1.log 2>&1 || exit 4
readelf -A deps1.tree/opt/lib/lib1.so >> deps1.log 2>&1 || exit 5
readelf -A deps1.tree/usr/lib/lib2.so >> deps1.log 2>&1 || exit 6
readelf -A deps1.tree/usr/lib/lib3.so >> deps1.log 2>&1 || exit 7
readelf -A deps1.tree/usr/bin/bin1 >> deps1.log 2>&1 || exit 8
LIBS="deps1.tree/usr/lib/lib1.so deps1.tree/usr/lib/lib2.so"
LIBS="$LIBS deps1.tree/opt/lib/lib1.so"
readelf -S deps1.tree/usr/lib/lib3.so | grep -q .gnu.prelink_undo \
  && LIBS="$LIBS deps1.tree/usr/lib/lib3.so"
readelf -S deps1.tree/usr/bin/bin1 | grep -q .gnu.prelink_undo \
  || BINS=
comparelibs >> deps1.log 2>&1 || exit 8
exit 0
