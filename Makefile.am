## Process this file with automake to produce Makefile.in

SUBDIRS = src 
ACLOCAL_AMFLAGS = \
	$(ACLOCAL_AMFLAGS) \
	-I m4

MAINTAINERCLEANFILES = aclocal.m4 Makefile.in \
                config.guess config.sub configure \
                depcomp install-sh ltmain.sh \
                missing compile config.h.in~  \
                m4/libtool.m4 m4/ltoptions.m4 \
                m4/ltsugar.m4 m4/ltversion.m4 \
                m4/lt~obsolete.m4 \
		src/config.h.in src/Makefile.in

# Remove doc directory on uninstall
uninstall-local:
	-rm -r $(docdir)
