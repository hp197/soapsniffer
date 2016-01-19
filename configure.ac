dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.50)
AC_INIT(soapsniff, 1.0)

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/config.h])

AM_INIT_AUTOMAKE([1.11 tar-pax dist-bzip2 foreign])
AM_SILENT_RULES([yes])

AC_CONFIG_SRCDIR(src/soapsniff.c)
AC_PREFIX_DEFAULT("/usr/local/")

AM_MAINTAINER_MODE

AC_PROG_CC_STDC
AC_PROG_CC
AC_PROG_INSTALL

LT_INIT


AC_MSG_NOTICE([checking for header files])
AC_DEFINE(_GNU_SOURCE, 1, [ Define to enable GNU extensions in glibc ])
AC_HEADER_STDC

AC_CHECK_HEADERS_ONCE([
	string.h stdio.h ctype.h arpa/inet.h netinet/ip.h netinet/tcp.h
])


AC_MSG_CHECKING([lib pcre])
AC_ARG_WITH(pcre,
[  --with-pcre[[=prefix]]    compile xmlpcre part (via libpcre check)],,
     with_pcre="yes")
if test ".$with_pcre" = ".no" ; then
  AC_MSG_RESULT([disabled])
  m4_ifval($2,$2)
else
  AC_MSG_RESULT([(testing)])
  AC_CHECK_LIB(pcre, pcre_study)
  if test "$ac_cv_lib_pcre_pcre_study" = "yes" ; then
     PCRE_LIBS="-lpcre"
     AC_MSG_CHECKING([lib pcre])
     AC_MSG_RESULT([$PCRE_LIBS])
     m4_ifval($1,$1)
  else
     OLDLDFLAGS="$LDFLAGS" ; LDFLAGS="$LDFLAGS -L$with_pcre/lib"
     OLDCPPFLAGS="$CPPFLAGS" ; CPPFLAGS="$CPPFLAGS -I$with_pcre/include"
     AC_CHECK_LIB(pcre, pcre_compile)
     CPPFLAGS="$OLDCPPFLAGS"
     LDFLAGS="$OLDLDFLAGS"
     if test "$ac_cv_lib_pcre_pcre_compile" = "yes" ; then
        AC_MSG_RESULT(.setting PCRE_LIBS -L$with_pcre/lib -lpcre)
        PCRE_LIBS="-L$with_pcre/lib -lpcre"
        test -d "$with_pcre/include" && PCRE_CFLAGS="-I$with_pcre/include"
        AC_MSG_CHECKING([lib pcre])
        AC_MSG_RESULT([$PCRE_LIBS])
        m4_ifval($1,$1)
     else
        AC_MSG_CHECKING([lib pcre])
        AC_MSG_RESULT([no, (ERROR)])
        m4_ifval($2,$2)
     fi
  fi
fi
AC_SUBST([PCRE_LIBS])
AC_SUBST([PCRE_CFLAGS])


AC_MSG_CHECKING([lib pcap])
AC_ARG_WITH(pcre,
[  --with-pcap[[=prefix]]    compile pcap part (via libpcap check)],,
     with_pcap="yes")
if test ".$with_pcap" = ".no" ; then
  AC_MSG_RESULT([disabled])
  m4_ifval($2,$2)
else
  AC_MSG_RESULT([(testing)])
  AC_CHECK_LIB(pcap, pcap_lookupdev)
  if test "$ac_cv_lib_pcap_pcap_lookupdev" = "yes" ; then
     PCAP_LIBS="-lpcap"
     AC_MSG_CHECKING([lib pcap])
     AC_MSG_RESULT([$PCAP_LIBS])
     m4_ifval($1,$1)
  else
     OLDLDFLAGS="$LDFLAGS" ; LDFLAGS="$LDFLAGS -L$with_pcap/lib"
     OLDCPPFLAGS="$CPPFLAGS" ; CPPFLAGS="$CPPFLAGS -I$with_pcap/include"
     AC_CHECK_LIB(pcap, pcap_lookupdev)
     CPPFLAGS="$OLDCPPFLAGS"
     LDFLAGS="$OLDLDFLAGS"
     if test "$ac_cv_lib_pcap_pcap_lookupdev" = "yes" ; then
        AC_MSG_RESULT(.setting PCAP_LIBS -L$with_pcap/lib -lpcap)
        PCAP_LIBS="-L$with_pcap/lib -lpcap"
        test -d "$with_pcap/include" && PCAP_CFLAGS="-I$with_pcap/include"
        AC_MSG_CHECKING([lib pcap])
        AC_MSG_RESULT([$PCAP_LIBS])
        m4_ifval($1,$1)
     else
        AC_MSG_CHECKING([lib pcap])
        AC_MSG_RESULT([no, (ERROR)])
        m4_ifval($2,$2)
     fi
  fi
fi
AC_SUBST([PCAP_LIBS])
AC_SUBST([PCAP_CFLAGS])

AC_OUTPUT([
Makefile
src/Makefile
])

cat <<EOF

Configuration summary
=====================

* Compilation environment

  CC       = $CC
  CFLAGS   = $CFLAGS
  CPP      = $CPP
  CPPFLAGS = $CPPFLAGS
  LD       = $LD
  LDFLAGS  = $LDFLAGS
  LIBS     = $LIBS

EOF
