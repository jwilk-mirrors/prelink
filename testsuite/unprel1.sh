#!/bin/bash
. `dirname $0`/functions.sh
PRELINK=`echo $PRELINK \
	 | sed -e 's, \./\(prelink\.\(cache\|conf\)\), unprel1.tree/etc/\1,g' \
	       -e 's,path=\.,path=unprel1.tree/opt:unprel1.tree/lib,' \
	       -e 's,linker=\./,linker=unprel1.tree/lib/,'`
CCLINK=`echo $CCLINK \
	| sed -e 's,linker=\./,linker=unprel1.tree/lib/,'`
rm -rf unprel1.tree
rm -f unprel1.log
mkdir -p unprel1.tree/{lib,etc,opt,bin}
$CC -shared -O2 -fpic -o unprel1.tree/lib/lib1.so $srcdir/unprel1lib1.c
cp -a unprel1.tree/{lib,opt}/lib1.so
$CC -shared -O2 -fpic -o unprel1.tree/lib/lib2.so $srcdir/unprel1lib2.c \
    -L unprel1.tree/lib -l1
$CCLINK -o unprel1.tree/bin/bin1 $srcdir/unprel1.c \
    -Wl,-rpath,unprel1.tree/lib -L unprel1.tree/lib -l2
cat > unprel1.tree/etc/prelink.conf <<EOF
unprel1.tree/bin
unprel1.tree/lib
EOF
for lib in `cat syslib.list`; do
  cp -p $lib.orig unprel1.tree/lib/$lib
  cp -p $lib.orig unprel1.tree/lib/$lib.orig
done
for lib in `cat syslnk.list`; do
  cp -dp $lib unprel1.tree/lib
done
LIBS="unprel1.tree/lib/lib1.so unprel1.tree/lib/lib2.so"
LIBS="$LIBS unprel1.tree/opt/lib1.so"
BINS="unprel1.tree/bin/bin1"
savelibs
chmod -x unprel1.tree/bin/bin1.orig
echo $PRELINK ${PRELINK_OPTS--vm} unprel1.tree/{bin,lib} > unprel1.log
$PRELINK ${PRELINK_OPTS--vm} unprel1.tree/{bin,lib} >> unprel1.log 2>&1 || exit 1
grep -v 'opt/lib1.so is not present in any config file directories' unprel1.log \
  | grep -v 'lib/lib2.so because its dependency unprel1.tree/opt/lib1.so could not be prelinked' \
  | grep -v 'bin/bin1 because its dependency unprel1.tree/lib/lib2.so could not be prelinked' \
  | grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` && exit 2
grep -q 'opt/lib1.so is not present in any config file directories' \
  unprel1.log || exit 3
grep -q 'lib/lib2.so because its dependency unprel1.tree/opt/lib1.so could not be prelinked' \
  unprel1.log || exit 4
grep -q 'bin/bin1 because its dependency unprel1.tree/lib/lib2.so could not be prelinked' \
  unprel1.log || exit 5
unprel1.tree/bin/bin1 || exit 6
# So that it is not prelinked again
chmod -x unprel1.tree/bin/bin1
LIBS=unprel1.tree/lib/lib1.so
BINS=
comparelibs >> unprel1.log 2>&1 || exit 7
for i in unprel1.tree/lib/lib2.so unprel1.tree/opt/lib1.so unprel1.tree/bin/bin1; do
  cmp -s $i $i.orig || exit 8
done
exit 0
