SHELL = /bin/sh

srcdir = .
top_srcdir = .
prefix = /usr/local
exec_prefix = ${prefix}

bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
libexecdir = ${exec_prefix}/libexec
datadir = ${prefix}/share
sysconfdir = ${prefix}/etc
sharedstatedir = ${prefix}/com
localstatedir = ${prefix}/var
libdir = ${exec_prefix}/lib
infodir = ${prefix}/info
mandir = ${prefix}/man
includedir = ${prefix}/include
oldincludedir = /usr/include

DESTDIR =

pkgdatadir = $(datadir)/snort
pkglibdir = $(libdir)/snort
pkgincludedir = $(includedir)/snort

top_builddir = .

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}
INSTALL_STRIP_FLAG =
transform = s,x,x,

POST_UNINSTALL = :
host_alias = x86_64-pc-linux-gnu
host_triplet = 
CC = gcc
MAKEINFO = /home/wendi/nfs/snort-1.3/missing makeinfo
PACKAGE = snort
VERSION = 1.3
extra_incl = 

bin_PROGRAMS = snort
snort_SOURCES = snort.c snort.h log.c log.h decode.c decode.h mstring.h mstring.c rules.c rules.h 
EXTRA_DIST = RULES.SAMPLE CREDITS snort-lib USAGE overflow-lib misc-lib scan-lib web-lib backdoor-lib
INCLUDES = 

PROGRAMS =  $(bin_PROGRAMS)


DEFS = -DHAVE_CONFIG_H -I. -I$(srcdir) -I.
CPPFLAGS = 
LDFLAGS = 
LIBS = -lpcap 
snort_OBJECTS =  snort.o log.o decode.o mstring.o rules.o
snort_LDADD = $(LDADD)
snort_DEPENDENCIES = 
snort_LDFLAGS = 
CFLAGS = -g -O2 -Wall 
COMPILE = $(CC) $(DEFS) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
CCLD = $(CC)
LINK = $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@


SOURCES = $(snort_SOURCES)
OBJECTS = $(snort_OBJECTS)



snort: $(snort_OBJECTS) $(snort_DEPENDENCIES)
	@rm -f snort
	$(LINK) $(snort_LDFLAGS) $(snort_OBJECTS) $(snort_LDADD) $(LIBS)





clean: 
	@rm -fv *.o
	@rm -fv snort



.PHONY: clean
