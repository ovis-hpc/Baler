bin_PROGRAMS =
lib_LTLIBRARIES =
AM_CFLAGS = -I@top_srcdir@/src/ -D_GNU_SOURCE

AM_YFLAGS = -d
AM_LFLAGS = -F
libsyslog_parser_la_SOURCES = syslog_parser.y syslog_lexer.l syslog.h
libsyslog_parser_la_CFLAGS = $(AM_CFLAGS)
libsyslog_parser_la_LIBADD = ../baler/libbaler.la -ly -ll -lc
# libsyslog_parser_la_LDFLAGS = -g -O0
lib_LTLIBRARIES += libsyslog_parser.la

libcraylog_parser_la_SOURCES = craylog_parser.y craylog_lexer.l craylog.h
libcraylog_parser_la_CFLAGS = $(AM_CFLAGS)
libcraylog_parser_la_LIBADD = ../baler/libbaler.la -ly -ll -lc
lib_LTLIBRARIES += libcraylog_parser.la

libbstore_sos_la_SOURCES = bstore_sos.c
libbstore_sos_la_CFLAGS = $(AM_CFLAGS) @SOS_INCDIR_FLAG@
libbstore_sos_la_LIBADD = ../baler/libbaler.la -lsos @SOS_LIBDIR_FLAG@ @SOS_LIB64DIR_FLAG@
# libbstore_sos_la_LDFLAGS = -pg -g
lib_LTLIBRARIES += libbstore_sos.la

libbstore_agg_la_SOURCES = bstore_agg.c
libbstore_agg_la_CFLAGS = $(AM_CFLAGS) @SOS_INCDIR_FLAG@
libbstore_agg_la_LIBADD = ../baler/libbaler.la -lsos -lpthread \
			  @SOS_LIBDIR_FLAG@ @SOS_LIB64DIR_FLAG@
lib_LTLIBRARIES += libbstore_agg.la

libbin_tcp_la_SOURCES = bin_tcp.c
libbin_tcp_la_CFLAGS = $(AM_CFLAGS) @LIBEVENT_INCDIR_FLAG@
libbin_tcp_la_LIBADD = -levent -levent_pthreads -L@LIBEVENT_LIBDIR@ \
		       -lpthread -ldl ../baler/libbaler.la
lib_LTLIBRARIES += libbin_tcp.la

libbin_udp_la_SOURCES = bin_udp.c
libbin_udp_la_CFLAGS = $(AM_CFLAGS)
libbin_udp_la_LIBADD = -lpthread -ldl ../baler/libbaler.la
lib_LTLIBRARIES += libbin_udp.la

libbout_store_msg_la_SOURCES = bout_store_msg.c bout_store_msg.h
libbout_store_msg_la_CFLAGS = $(AM_CFLAGS)
libbout_store_msg_la_LIBADD = ../baler/libbaler.la -lpthread
lib_LTLIBRARIES += libbout_store_msg.la

libbout_store_hist_la_SOURCES = bout_store_hist.c bout_store_hist.h
libbout_store_hist_la_CFLAGS = $(AM_CFLAGS)
libbout_store_hist_la_LIBADD = ../baler/libbaler.la -lpthread
lib_LTLIBRARIES += libbout_store_hist.la

libbin_test_la_SOURCES = bin_test.c
libbin_test_la_CFLAGS = $(AM_CFLAGS)
libbin_test_la_LIBADD = ../baler/libbaler.la \
			-lpthread
lib_LTLIBRARIES += libbin_test.la
