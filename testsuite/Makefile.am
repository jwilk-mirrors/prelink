## Process this file with automake to create Makefile.in

AUTOMAKE_OPTIONS = 1.4 gnu

DEFS = -D_GNU_SOURCE -DHAVE_CONFIG_H -Wall
AM_CFLAGS = -Wall

TESTS = movelibs.sh \
	reloc1.sh reloc2.sh reloc3.sh reloc4.sh reloc5.sh reloc6.sh \
	reloc7.sh reloc8.sh reloc9.sh reloc10.sh reloc11.sh \
	shuffle1.sh shuffle2.sh shuffle3.sh shuffle4.sh shuffle5.sh \
	shuffle6.sh shuffle7.sh shuffle8.sh shuffle9.sh undo1.sh \
	layout1.sh layout2.sh \
	tls1.sh tls2.sh tls3.sh tls4.sh tls5.sh tls6.sh tls7.sh \
	cxx1.sh cxx2.sh quick1.sh quick2.sh quick3.sh cycle1.sh cycle2.sh \
	deps1.sh deps2.sh \
	undosyslibs.sh
TESTS_ENVIRONMENT = \
	PRELINK="../src/prelink -c ./prelink.conf -C ./prelink.cache --ld-library-path=. --dynamic-linker=`echo ./ld*.so.*[0-9]`" \
	CC="$(CC) $(LINKOPTS)" CCLINK="$(CC) -Wl,--dynamic-linker=`echo ./ld*.so.*[0-9]`" \
	CXX="$(CXX) $(LINKOPTS)" CXXLINK="$(CXX) -Wl,--dynamic-linker=`echo ./ld*.so.*[0-9]`" \
	$(SHELL)

extra_DIST = $(TESTS) functions.sh

CLEANFILES = *.so *.so.* *.nop syslib.list syslnk.list prelink.cache prelink.conf \
	$(TESTS:%.sh=%) $(TESTS:%.sh=%.log) $(TESTS:%.sh=%.lds) \
	*.orig *.new core* *.\#prelink\#* tlstest *.first *.second

clean-am: clean-dirs

clean-dirs:
	rm -rf *.tree

.NOTPARALLEL:

check-cycle:
	@optlist=.; \
	if [ "`uname -m | sed s/i.86/i.86/`" = i.86 ]; then \
	  optlist="--no-exec-shield --exec-shield"; \
	fi; \
	for opts2 in $$optlist; do \
	  for opts in -v -vm -vR -vmR; do \
	    PRELINK_OPTS="$$opts"; \
	    [ $$opts2 != . ] && PRELINK_OPTS="$$opts $$opts2"; \
	    echo "Checking with $$PRELINK_OPTS"; \
	    PRELINK_OPTS="$$PRELINK_OPTS" $(MAKE) $(AM_MAKEFLAGS) check || exit; \
	    $(MAKE) $(AM_MAKEFLAGS) clean || exit; \
	  done; \
	done; \
	echo "Checking with -Wl,-z,nocombreloc"; \
	LINKOPTS=-Wl,-z,nocombreloc $(MAKE) $(AM_MAKEFLAGS) check || exit; \
	$(MAKE) $(AM_MAKEFLAGS) clean || exit

check-harder:
	@CHECK_ME_HARDER=1 $(MAKE) $(AM_MAKEFLAGS) check || exit
