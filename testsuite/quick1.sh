#!/bin/bash
. `dirname $0`/functions.sh
check_one() {
  cnt=0
  log=$1
  echo -n . >> quick1.log
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
  echo -n "Checking $1 " >> quick1.log
  check_one $log 'Checking executable' $CHECKE
  check_one $log 'Checking shared library' $CHECKL
  check_one $log 'Assuming prelinked' $ASSUME
  check_one $log 'Prelinking' $PREL
  echo >> quick1.log
}

PRELINK=`echo $PRELINK \
	 | sed -e 's, \./\(prelink\.\(cache\|conf\)\), quick1.tree/etc/\1,g' \
	       -e 's,path=\.,path=quick1.tree/lib:quick1.tree/usr/lib,' \
	       -e 's,linker=\./,linker=quick1.tree/lib/,'`
CCLINK=`echo $CCLINK \
	| sed -e 's,linker=\./,linker=quick1.tree/lib/,'`
rm -rf quick1.tree
rm -f quick1.log
mkdir -p quick1.tree/{lib,etc,usr/lib,usr/bin}
$CC -shared -O2 -fpic -o quick1.tree/usr/lib/lib1.so $srcdir/reloc1lib1.c
$CC -shared -O2 -fpic -o quick1.tree/usr/lib/lib2.so $srcdir/reloc1lib2.c \
    -L quick1.tree/usr/lib -l1
$CC -shared -O2 -fpic -o quick1.tree/usr/lib/lib3.so $srcdir/quick1lib1.c
$CC -shared -O2 -fpic -o quick1.tree/usr/lib/lib2.later.so \
    $srcdir/quick1lib2.c -L quick1.tree/usr/lib -l1 -l3
echo 'int foo;' | $CC -shared -O2 -fpic -o quick1.tree/usr/lib/lib4.so -xc -
$CC -shared -O2 -fpic -o quick1.tree/usr/lib/lib5.so $srcdir/quick1lib3.c \
    -L quick1.tree/usr/lib -Wl,--rpath-link,quick1.tree/usr/lib -l2
$CC -shared -O2 -fpic -o quick1.tree/usr/lib/lib6.so $srcdir/quick1lib4.c \
    -L quick1.tree/usr/lib -Wl,--rpath-link,quick1.tree/usr/lib -l5
echo 'int baz;' | $CC -shared -O2 -fpic -o quick1.tree/usr/lib/lib7.so -xc - \
    -L quick1.tree/usr/lib -Wl,--rpath-link,quick1.tree/usr/lib -l6
echo 'int baz;' | $CC -shared -O2 -fpic -o quick1.tree/usr/lib/lib7.later.so \
    -xc - -L quick1.tree/usr/lib -Wl,--rpath-link,quick1.tree/usr/lib -l2
for lib in `cat syslib.list`; do
  cp -p $lib.orig quick1.tree/lib/$lib
  cp -p $lib.orig quick1.tree/lib/$lib.orig
done
for lib in `cat syslnk.list`; do
  cp -dp $lib quick1.tree/lib
done
$CCLINK -o quick1.tree/usr/bin/bin1 $srcdir/reloc1.c \
    -Wl,--rpath-link,quick1.tree/usr/lib -L quick1.tree/usr/lib -l2
echo 'int main () { extern int foo; return foo; }' \
  | $CCLINK -o quick1.tree/usr/bin/bin2 -xc - -xnone \
    -L quick1.tree/usr/lib -l4
$CCLINK -o quick1.tree/usr/bin/bin3 $srcdir/reloc1.c \
    -Wl,--rpath-link,quick1.tree/usr/lib -L quick1.tree/usr/lib -l7
$CCLINK -o quick1.tree/usr/bin/bin4 $srcdir/quick1.c \
    -Wl,--rpath-link,quick1.tree/usr/lib -L quick1.tree/usr/lib -l2
$CCLINK -o quick1.tree/usr/bin/bin5 $srcdir/quick1.c \
    -Wl,--rpath-link,quick1.tree/usr/lib -L quick1.tree/usr/lib -l7
echo 'int main () { return 0; }' \
  | $CCLINK -o quick1.tree/usr/bin/bin6 -xc - -xnone \
    -Wl,--rpath-link,quick1.tree/usr/lib -L quick1.tree/usr/lib -l6
cat > quick1.tree/etc/prelink.conf <<EOF
quick1.tree/usr/bin
quick1.tree/lib
quick1.tree/usr/lib
EOF
LIBS="quick1.tree/usr/lib/lib1.so quick1.tree/usr/lib/lib2.so"
LIBS="$LIBS quick1.tree/usr/lib/lib3.so quick1.tree/usr/lib/lib4.so"
LIBS="$LIBS quick1.tree/usr/lib/lib5.so quick1.tree/usr/lib/lib6.so"
LIBS="$LIBS quick1.tree/usr/lib/lib7.so"
LIBS="$LIBS `sed 's|^|quick1.tree/lib/|' syslib.list`"
BINS="quick1.tree/usr/bin/bin1 quick1.tree/usr/bin/bin2"
BINS="$BINS quick1.tree/usr/bin/bin3 quick1.tree/usr/bin/bin4"
BINS="$BINS quick1.tree/usr/bin/bin5 quick1.tree/usr/bin/bin6"
savelibs
chmod 644 `ls $BINS | sed 's|$|.orig|'`
# Make sure prelinked binaries and libraries will have different ctimes
# than mtimes
sleep 3s
# lib2.later.so needs different timestamps than lib2.so for the tests below
touch quick1.tree/usr/lib/lib2.later.so
cp -p quick1.tree/usr/lib/lib2.later.so{,.orig}
# lib7.later.so needs different timestamps than lib7.so for the tests below
touch quick1.tree/usr/lib/lib7.later.so
cp -p quick1.tree/usr/lib/lib7.later.so{,.orig}
echo $PRELINK ${PRELINK_OPTS--vm} -avvvvv > quick1.log
$PRELINK ${PRELINK_OPTS--vm} -avvvvv > quick1.tree/etc/log1 2>&1 || exit 1
cat quick1.tree/etc/log1 >> quick1.log
echo $PRELINK ${PRELINK_OPTS--vm} -aqvvvvv >> quick1.log
$PRELINK ${PRELINK_OPTS--vm} -aqvvvvv > quick1.tree/etc/log2 2>&1 || exit 2
cat quick1.tree/etc/log2 >> quick1.log
stat quick1.tree/usr/lib/lib2.so >> quick1.log
echo chmod 644 quick1.tree/usr/lib/lib2.so >> quick1.log
chmod 644 quick1.tree/usr/lib/lib2.so
sleep 3s
echo chmod 755 quick1.tree/usr/lib/lib2.so >> quick1.log
chmod 755 quick1.tree/usr/lib/lib2.so
stat quick1.tree/usr/lib/lib2.so >> quick1.log
echo $PRELINK ${PRELINK_OPTS--vm} -aqvvvvv >> quick1.log
$PRELINK ${PRELINK_OPTS--vm} -aqvvvvv > quick1.tree/etc/log3 2>&1 || exit 3
cat quick1.tree/etc/log3 >> quick1.log
echo $PRELINK ${PRELINK_OPTS--vm} -aqvvvvv >> quick1.log
$PRELINK ${PRELINK_OPTS--vm} -aqvvvvv > quick1.tree/etc/log4 2>&1 || exit 4
cat quick1.tree/etc/log4 >> quick1.log
LD_LIBRARY_PATH=quick1.tree/lib:quick1.tree/usr/lib quick1.tree/usr/bin/bin1 || exit 5
LD_LIBRARY_PATH=quick1.tree/lib:quick1.tree/usr/lib quick1.tree/usr/bin/bin2 || exit 6
LD_LIBRARY_PATH=quick1.tree/lib:quick1.tree/usr/lib quick1.tree/usr/bin/bin3 || exit 7
LD_LIBRARY_PATH=quick1.tree/lib:quick1.tree/usr/lib quick1.tree/usr/bin/bin4 || exit 8
LD_LIBRARY_PATH=quick1.tree/lib:quick1.tree/usr/lib quick1.tree/usr/bin/bin5 || exit 9
LD_LIBRARY_PATH=quick1.tree/lib:quick1.tree/usr/lib quick1.tree/usr/bin/bin6 || exit 10
readelf -a quick1.tree/usr/bin/bin1 >> quick1.log 2>&1 || exit 11
readelf -a quick1.tree/usr/bin/bin3 >> quick1.log 2>&1 || exit 12
readelf -a quick1.tree/usr/bin/bin4 >> quick1.log 2>&1 || exit 13
readelf -a quick1.tree/usr/bin/bin5 >> quick1.log 2>&1 || exit 14
readelf -a quick1.tree/usr/bin/bin6 >> quick1.log 2>&1 || exit 15
BINS="quick1.tree/usr/bin/bin1 quick1.tree/usr/bin/bin3"
BINS="$BINS quick1.tree/usr/bin/bin4 quick1.tree/usr/bin/bin5"
BINS="$BINS quick1.tree/usr/bin/bin6"
LIBS="quick1.tree/usr/lib/lib2.so quick1.tree/usr/lib/lib7.so"
comparelibs >> quick1.log 2>&1 || exit 16
for l in 2 7; do
  mv -f quick1.tree/usr/lib/lib$l.so{,.old}
  mv -f quick1.tree/usr/lib/lib$l.so{,.old}.orig
  cp -p quick1.tree/usr/lib/lib$l{.later,}.so
  cp -p quick1.tree/usr/lib/lib$l{.later,}.so.orig
done
for b in 1 3 4 5 6; do
  cp -p quick1.tree/usr/bin/bin$b{,.old}
  chmod 644 quick1.tree/usr/bin/bin$b.old
done
echo $PRELINK ${PRELINK_OPTS--vm} -aqvvvvv >> quick1.log
$PRELINK ${PRELINK_OPTS--vm} -aqvvvvv > quick1.tree/etc/log5 2>&1 || exit 17
cat quick1.tree/etc/log5 >> quick1.log
LD_LIBRARY_PATH=quick1.tree/lib:quick1.tree/usr/lib quick1.tree/usr/bin/bin1 || exit 18
LD_LIBRARY_PATH=quick1.tree/lib:quick1.tree/usr/lib quick1.tree/usr/bin/bin2 || exit 19
LD_LIBRARY_PATH=quick1.tree/lib:quick1.tree/usr/lib quick1.tree/usr/bin/bin3 || exit 20
LD_LIBRARY_PATH=quick1.tree/lib:quick1.tree/usr/lib quick1.tree/usr/bin/bin4 || exit 21
LD_LIBRARY_PATH=quick1.tree/lib:quick1.tree/usr/lib quick1.tree/usr/bin/bin5 || exit 22
LD_LIBRARY_PATH=quick1.tree/lib:quick1.tree/usr/lib quick1.tree/usr/bin/bin6 || exit 23
readelf -a quick1.tree/usr/bin/bin1 >> quick1.log 2>&1 || exit 24
readelf -a quick1.tree/usr/bin/bin3 >> quick1.log 2>&1 || exit 25
readelf -a quick1.tree/usr/bin/bin4 >> quick1.log 2>&1 || exit 26
readelf -a quick1.tree/usr/bin/bin5 >> quick1.log 2>&1 || exit 27
readelf -a quick1.tree/usr/bin/bin6 >> quick1.log 2>&1 || exit 28
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` quick1.log && exit 29
L=quick1.tree/usr/lib/lib
L1=${L}1.so; L2=${L}2.so; L3=${L}3.so; L4=${L}4.so
L5=${L}5.so; L6=${L}6.so; L7=${L}7.so
B=quick1.tree/usr/bin/bin
B1=${B}1; B2=${B}2; B3=${B}3; B4=${B}4; B5=${B}5; B6=${B}6
SL=`grep -f syslib.list quick1.tree/etc/log1 \
    | sed -n '/^Prelinking/s|^.*\(quick1.tree/lib/\)|\1|p'`
CHECKE="$B1 $B2 $B3 $B4 $B5 $B6"; CHECKL="$SL $L1 $L2 $L4 $L5 $L6 $L7" PREL="$CHECKE $CHECKL"; ASSUME=""
check_log quick1.tree/etc/log1
CHECKE=""; CHECKL=""; PREL=""; ASSUME="$B1 $B2 $B3 $B4 $B5 $B6 $SL $L1 $L2 $L4 $L5 $L6 $L7"
check_log quick1.tree/etc/log2
CHECKE="$B1 $B3 $B4 $B5 $B6"; CHECKL="$SL $L1 $L2 $L5 $L6 $L7"; PREL=""; ASSUME="$B2 $L4"
check_log quick1.tree/etc/log3
CHECKE=""; CHECKL=""; PREL=""; ASSUME="$B1 $B2 $B3 $B4 $B5 $B6 $SL $L1 $L2 $L4 $L5 $L6 $L7"
check_log quick1.tree/etc/log4
CHECKE="$B1 $B3 $B4 $B5 $B6"; CHECKL="$SL $L1 $L2 $L3 $L5 $L7 $L7"; PREL="$B1 $B3 $B4 $B5 $B6 $L2 $L3 $L5 $L6 $L7"; ASSUME="$B2 $L4"
check_log quick1.tree/etc/log5
BINS="$B1 $B2 $B3 $B4 $B5 $B6"
LIBS="$SL $L1 $L2 $L3 $L4 $L5 $L6 $L7 $L2.old"
comparelibs >> quick1.log 2>&1 || exit 30
for i in $BINS $SL $L1 $L2 $L3 $L4 $L5 $L6 $L7; do
  cp -p $i $i.prelinked
done
for i in $BINS; do
  chmod 644 $i.prelinked
done
echo $PRELINK -uavvvvvv >> quick1.log
$PRELINK -uavvvvvv >> quick1.log 2>&1 || exit 31
for i in $BINS $SL $L1 $L2 $L3 $L4 $L5 $L6 $L7; do
  cmp -s $i.orig $i || exit 32
  mv -f $i.prelinked $i
done
chmod 755 $BINS
exit 0
