#!/bin/bash
. `dirname $0`/functions.sh

PRELINK=`echo $PRELINK \
	 | sed -e 's, \./\(prelink\.\(cache\|conf\)\), deps2.tree/etc/\1,g' \
	       -e 's,path=\.,path=deps2.tree/lib:deps2.tree/usr/lib:deps2.tree/opt/lib,' \
	       -e 's,linker=\./,linker=deps2.tree/lib/,'`
CCLINK=`echo $CCLINK \
	| sed -e 's,linker=\./,linker=deps2.tree/lib/,'`
rm -rf deps2.tree
rm -f deps2.log
mkdir -p deps2.tree/{lib,etc,usr/lib,opt/lib,usr/bin}
$CC -shared -O2 -fpic -o deps2.tree/usr/lib/lib1.so $srcdir/deps1lib1.c
$CC -shared -O2 -fpic -o deps2.tree/opt/lib/lib1.so $srcdir/deps2lib1.c
$CC -shared -O2 -fpic -o deps2.tree/usr/lib/lib2.so $srcdir/deps1lib2.c \
    -L deps2.tree/opt/lib -Wl,-rpath,deps2.tree/opt/lib -l1
echo '' | $CC -shared -O2 -fpic -o deps2.tree/usr/lib/lib3.so -xc - -xnone \
    -L deps2.tree/usr/lib -L deps2.tree/opt/lib -Wl,-rpath,deps2.tree/usr/lib \
    -l1 -l2
for lib in `cat syslib.list`; do
  cp -p $lib.orig deps2.tree/lib/$lib
  cp -p $lib.orig deps2.tree/lib/$lib.orig
done
for lib in `cat syslnk.list`; do
  cp -dp $lib deps2.tree/lib
done
$CCLINK -o deps2.tree/usr/bin/bin1 $srcdir/deps1.c \
    -Wl,-rpath,deps2.tree/usr/lib -L deps2.tree/usr/lib -l3 -lc -l1 -l2
cat > deps2.tree/etc/prelink.conf <<EOF
deps2.tree/usr/bin
deps2.tree/lib
deps2.tree/usr/lib
deps2.tree/opt/lib
EOF
LIBS="deps2.tree/usr/lib/lib1.so deps2.tree/usr/lib/lib2.so"
LIBS="$LIBS deps2.tree/usr/lib/lib3.so deps2.tree/opt/lib/lib1.so"
LIBS="$LIBS `sed 's|^|deps2.tree/lib/|' syslib.list`"
BINS="deps2.tree/usr/bin/bin1"
savelibs
chmod 644 `ls $BINS | sed 's|$|.orig|'`
echo $PRELINK ${PRELINK_OPTS--v} -avvvvv > deps2.log
$PRELINK ${PRELINK_OPTS--v} -avvvvv > deps2.tree/etc/log1 2>&1 || exit 1
cat deps2.tree/etc/log1 >> deps2.log
LD_LIBRARY_PATH=deps2.tree/lib deps2.tree/usr/bin/bin1 || exit 2
readelf -d deps2.tree/{usr,opt}/lib/lib1.so 2>&1 | grep CHECKSUM >> deps2.log || exit 3
readelf -A deps2.tree/usr/lib/lib1.so >> deps2.log 2>&1 || exit 4
readelf -A deps2.tree/opt/lib/lib1.so >> deps2.log 2>&1 || exit 5
readelf -A deps2.tree/usr/lib/lib2.so >> deps2.log 2>&1 || exit 6
readelf -A deps2.tree/usr/lib/lib3.so >> deps2.log 2>&1 || exit 7
readelf -A deps2.tree/usr/bin/bin1 >> deps2.log 2>&1 || exit 8
LIBS="deps2.tree/usr/lib/lib1.so deps2.tree/usr/lib/lib2.so"
LIBS="$LIBS deps2.tree/opt/lib/lib1.so"
BINS=
comparelibs >> deps2.log 2>&1 || exit 9
exit 0
