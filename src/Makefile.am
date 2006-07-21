## Process this file with automake to create Makefile.in

AUTOMAKE_OPTIONS = 1.4 gnu

DEFS = -D_GNU_SOURCE -DHAVE_CONFIG_H -Wall
AM_CFLAGS = -Wall
AM_CPPFLAGS = -DSBINDIR='"@sbindir@"'
INCLUDES = @GELFINCLUDE@

sbin_PROGRAMS = prelink
bin_PROGRAMS = execstack

arch_SOURCES = arch-i386.c arch-alpha.c arch-ppc.c arch-ppc64.c \
	       arch-sparc.c arch-sparc64.c arch-x86_64.c \
	       arch-s390.c arch-s390x.c arch-arm.c arch-sh.c arch-ia64.c
common_SOURCES = checksum.c data.c dso.c dwarf2.c dwarf2.h fptr.c fptr.h     \
		 hashtab.c hashtab.h mdebug.c prelink.h stabs.c crc32.c
prelink_SOURCES = cache.c conflict.c cxx.c doit.c exec.c execle_open.c get.c \
		  gather.c layout.c main.c prelink.c     \
		  prelinktab.h reloc.c reloc.h space.c undo.c undoall.c      \
		  verify.c canonicalize.c md5.c md5.h sha.c sha.h 	     \
		  $(common_SOURCES) $(arch_SOURCES)
prelink_LDADD = @LIBGELF@
prelink_LDFLAGS = -all-static

execstack_SOURCES = execstack.c $(common_SOURCES) $(arch_SOURCES)

extra_DIST = makecrc.c
