lib_LTLIBRARIES =
bin_PROGRAMS =

EXTRA_DIST = n2dassoc.dox

AM_CFLAGS = -I$(srcdir)/../ -D_GNU_SOURCE

pkginclude_HEADERS = assoc.h \
		     n2da.h \
		     n2dassoc.h

libassoc_la_SOURCES = assoc.c assoc.h
libassoc_la_CFLAGS = $(AM_CFLAGS) -pthread
lib_LTLIBRARIES += libassoc.la

assoc_rule_dump_SOURCES = assoc_rule_dump.c
assoc_rule_dump_LDADD = libassoc.la
bin_PROGRAMS += assoc_rule_dump

libn2da_la_SOURCES = n2da.c n2da.h
lib_LTLIBRARIES += libn2da.la

libn2dassoc_la_SOURCES = n2dassoc.c n2dassoc.h
libn2dassoc_la_CFLAGS = $(AM_CFLAGS) -pthread -DLIBN2DASSOC
libn2dassoc_la_LIBADD = libn2da.la libassoc.la
libn2dassoc_la_LDFLAGS = $(AM_LDFLAGS)
lib_LTLIBRARIES += libn2dassoc.la

n2dassoc_SOURCES = n2dassoc.c n2dassoc.h
n2dassoc_CFLAGS = $(AM_CFLAGS) -pthread
n2dassoc_LDADD = libn2da.la libassoc.la
bin_PROGRAMS += n2dassoc

if ENABLE_N2DA_TEST
n2da_test_SOURCES = n2da_test.c
n2da_test_CFLAGS = $(AM_CFLAGS)
n2da_test_LDADD = libn2da.la
bin_PROGRAMS += n2da_test

assoc_test_SOURCES = assoc_test.c
assoc_test_CFLAGS = $(AM_CFLAGS)
assoc_test_LDADD = libassoc.la
bin_PROGRAMS += assoc_test
endif
