## Process this file with automake to create Makefile.in

AUTOMAKE_OPTIONS = 1.4 gnu

man_MANS = prelink.8 execstack.8
EXTRA_DIST = prelink.8 execstack.8 prelink.conf
PDFLATEXINPUTS = TEXINPUTS_pdflatex=.:$(srcdir):`kpsewhich --progname=pdflatex --show-path=cnf.pdflatex`
LATEXINPUTS = TEXINPUTS_latex=.:$(srcdir):`kpsewhich --progname=latex --show-path=cnf.latex`

noinst_DATA = prelink.pdf
pics = gap bss basemove newseg dso1 dso2 dso3

prelink.pdf: prelink.tex $(pics:=.fig) linuxtag.sty \
	     prelinklisting.sty lineno.sty glossary.conf
	$(MAKE) $(pics:=.pdf)
	$(PDFLATEXINPUTS) pdflatex $<
	makeindex -s $(srcdir)/glossary.conf -o prelink.gls prelink.glo
	if grep -q Rerun prelink.log; then $(PDFLATEXINPUTS) pdflatex $<; fi
	thumbpdf $@ && $(PDFLATEXINPUTS) pdflatex $<
	mv $@ prelinkin.pdf
	pdfopt prelinkin.pdf $@
	rm prelinkin.pdf

prelink.ps: prelink.dvi
	dvips $< -o $@

prelink.dvi: prelink.tex $(pics:=.eps)
	$(LATEXINPUTS) latex $<
	if grep -q Rerun prelink.log; then $(LATEXINPUTS) latex $<; fi

SUFFIXES = .fig .eps .pdf

.fig.eps:
	fig2dev -L eps $^ $@

.fig.pdf:
	fig2dev -L pdf $^ $@

CLEANFILES = $(pics:=.eps) $(pics:=.pdf) prelink.aux prelink.dvi \
	     prelink.log prelink.mtc prelink.mtc1 prelink.pdf prelink.ps \
	     prelink.glo prelink.idx prelink.out prelink.tpt prelink.ilg \
	     prelink.gls prelink.toc
