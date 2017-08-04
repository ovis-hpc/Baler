lib_LTLIBRARIES =
bin_PROGRAMS =

AM_CFLAGS = -I$(srcdir)/../ -D_GNU_SOURCE

libbassocimg_la_SOURCES = bassocimg.c bassocimg.h
libbassocimg_la_LIBADD = ../baler/libbaler.la
libbassocimg_la_LDFLAGS = $(AM_LDFLAGS)
libbassocimg_la_CFLAGS = $(AM_CFLAGS)
lib_LTLIBRARIES += libbassocimg.la

bassoc_SOURCES =  bassoc.c bassoc.h
bassoc_LDADD = ../baler/libbaler.la \
	       libbassocimg.la \
	       -lpthread
bassoc_LDFLAGS = $(AM_LDFLAGS)
bassoc_CFLAGS = $(AM_CFLAGS)
bin_PROGRAMS += bassoc

bassocimg2pgm_SOURCES = bassocimg2pgm.c
bassocimg2pgm_LDADD = ../baler/libbaler.la libbassocimg.la
bassocimg2pgm_LDFLAGS = $(AM_LDFLAGS)
bassocimg2pgm_CFLAGS = $(AM_CFLAGS)
bin_PROGRAMS += bassocimg2pgm

bassocimg_dump_SOURCES = bassocimg_dump.c
bassocimg_dump_LDADD = ../baler/libbaler.la libbassocimg.la
bassocimg_dump_LDFLAGS = $(AM_LDFLAGS)
bassocimg_dump_CFLAGS = $(AM_CFLAGS)
bin_PROGRAMS += bassocimg_dump

bassocimg_intersect_test_SOURCES = bassocimg_intersect_test.c
bassocimg_intersect_test_LDADD = ../baler/libbaler.la libbassocimg.la
bassocimg_intersect_test_LDFLAGS = $(AM_LDFLAGS)
bassocimg_intersect_test_CFLAGS = $(AM_CFLAGS)
bin_PROGRAMS += bassocimg_intersect_test

bassocimg_cache_dump_SOURCES = bassocimg_cache_dump.c
bassocimg_cache_dump_LDADD = ../baler/libbaler.la libbassocimg.la
bassocimg_cache_dump_LDFLAGS = $(AM_LDFLAGS)
bassocimg_cache_dump_CFLAGS = $(AM_CFLAGS)
bin_PROGRAMS += bassocimg_cache_dump
