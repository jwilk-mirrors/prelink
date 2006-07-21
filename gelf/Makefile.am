## Process this file with automake to create Makefile.in

AUTOMAKE_OPTIONS = 1.4 gnu

DEFS = -D_GNU_SOURCE -DHAVE_CONFIG_H -Wall
AM_CFLAGS = -Wall
INCLUDES = @GELFINCLUDE@

noinst_LTLIBRARIES = libgelf.la

libgelf_la_SOURCES = gelf.c

noinst_HEADERS = gelf.h
