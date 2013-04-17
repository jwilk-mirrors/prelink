#!/bin/bash
. `dirname $0`/functions.sh
check_one() {
  cnt=0
  log=$1
  echo -n . >> quick3.log
  text="$2"
  shift 2
  while [ $# -gt 0 ]; do
    grep -q "^$text .*$1" $log || exit 40
    cnt=$((++cnt))
    shift
  done
  [ `grep "^$text " $log | wc -l` = $cnt ] || exit 41
}
check_log() {
  log=$1
  echo -n "Checking $1 " >> quick3.log
  check_one $log 'Checking executable' $CHECKE
  check_one $log 'Checking shared library' $CHECKL
  check_one $log 'Assuming prelinked' $ASSUME
  check_one $log 'Prelinking' $PREL
  echo >> quick3.log
}

PRELINK=`echo $PRELINK \
	 | sed -e 's, \./\(prelink\.\(cache\|conf\)\), quick3.tree/etc/\1,g' \
	       -e 's,path=\.,path=quick3.tree/lib:quick3.tree/usr/lib,' \
	       -e 's,linker=\./,linker=quick3.tree/lib/,'`
CCLINK=`echo $CCLINK \
	| sed -e 's,linker=\./,linker=quick3.tree/lib/,'`
rm -rf quick3.tree
rm -f quick3.log
mkdir -p quick3.tree/{lib,etc,usr/lib,usr/bin}
$CC -shared -O2 -fpic -o quick3.tree/usr/lib/lib1.so $srcdir/reloc1lib1.c
$CC -shared -O2 -fpic -o quick3.tree/usr/lib/lib2.so $srcdir/reloc1lib2.c \
    -L quick3.tree/usr/lib -l1 -Wl,-soname,lib2.so
for lib in `cat syslib.list`; do
  cp -p $lib.orig quick3.tree/lib/$lib
  cp -p $lib.orig quick3.tree/lib/$lib.orig
done
for lib in `cat syslnk.list`; do
  cp -dp $lib quick3.tree/lib
done
$CCLINK -o quick3.tree/usr/bin/bin1 $srcdir/reloc1.c \
    -Wl,--rpath-link,quick3.tree/usr/lib -L quick3.tree/usr/lib -l2 -lc -l1
cat > quick3.tree/etc/prelink.conf <<EOF
quick3.tree/usr/bin
quick3.tree/lib
quick3.tree/usr/lib
EOF
LIBS="quick3.tree/usr/lib/lib1.so quick3.tree/usr/lib/lib2.so"
LIBS="$LIBS `sed 's|^|quick3.tree/lib/|' syslib.list`"
BINS="quick3.tree/usr/bin/bin1"
savelibs
chmod 644 `ls $BINS | sed 's|$|.orig|'`
# Make sure prelinked binaries and libraries will have different ctimes
# than mtimes
sleep 3s
echo $PRELINK ${PRELINK_OPTS--vm} -avvvvv > quick3.log
$PRELINK ${PRELINK_OPTS--vm} -avvvvv > quick3.tree/etc/log1 2>&1 || exit 1
cat quick3.tree/etc/log1 >> quick3.log
echo $PRELINK ${PRELINK_OPTS--vm} -aqvvvvv >> quick3.log
$PRELINK ${PRELINK_OPTS--vm} -aqvvvvv > quick3.tree/etc/log2 2>&1 || exit 2
cat quick3.tree/etc/log2 >> quick3.log
$CC -shared -O2 -fpic -o quick3.tree/usr/lib/lib2.so.0 $srcdir/reloc1lib2.c \
    -L quick3.tree/usr/lib -l1 -Wl,-soname,lib2.so
rm -f quick3.tree/usr/lib/lib2.so{,.orig}
cp -p quick3.tree/usr/lib/lib2.so.0{,.orig}
ln -sf lib2.so.0 quick3.tree/usr/lib/lib2.so
sleep 3s
echo $PRELINK ${PRELINK_OPTS--vm} -aqvvvvv >> quick3.log
$PRELINK ${PRELINK_OPTS--vm} -aqvvvvv > quick3.tree/etc/log3 2>&1 || exit 3
cat quick3.tree/etc/log3 >> quick3.log
LD_LIBRARY_PATH=quick3.tree/lib:quick3.tree/usr/lib quick3.tree/usr/bin/bin1 || exit 4
LIBS="quick3.tree/usr/lib/lib1.so quick3.tree/usr/lib/lib2.so.0"
echo $PRELINK ${PRELINK_OPTS--vm} -aqvvvvv >> quick3.log
$PRELINK ${PRELINK_OPTS--vm} -aqvvvvv > quick3.tree/etc/log4 2>&1 || exit 5
cat quick3.tree/etc/log4 >> quick3.log
comparelibs >> quick3.log 2>&1 || exit 6
[ -L quick3.tree/usr/lib/lib2.so ] || exit 7
L=quick3.tree/usr/lib/lib
L1=${L}1.so; L2=${L}2.so; L3=${L}2.so.0
B1=quick3.tree/usr/bin/bin1
SL=`grep -f syslib.list quick3.tree/etc/log1 \
    | sed -n '/^Prelinking/s|^.*\(quick3.tree/lib/\)|\1|p'`
CHECKE="$B1"; CHECKL="$SL $L1 $L2" PREL="$CHECKE $CHECKL"; ASSUME=""
check_log quick3.tree/etc/log1
CHECKE=""; CHECKL=""; PREL=""; ASSUME="$B1 $L1 $L2 $SL"
check_log quick3.tree/etc/log2
CHECKE="$B1"; CHECKL="$SL $L1 $L3"; PREL="$B1 $L3"; ASSUME=""
check_log quick3.tree/etc/log3
CHECKE=""; CHECKL=""; PREL=""; ASSUME="$B1 $L1 $L3 $SL"
check_log quick3.tree/etc/log4
for i in $B1 $SL $L1 $L3; do
  cp -p $i $i.prelinked
done
for i in $B1; do
  chmod 644 $i.prelinked
done
echo $PRELINK -uavvvvvv >> quick3.log
$PRELINK -uavvvvvv >> quick3.log 2>&1 || exit 31
for i in $B1 $SL $L1 $L3; do
  cmp -s $i.orig $i || exit 32
  mv -f $i.prelinked $i
done
chmod 755 $BINS
exit 0
