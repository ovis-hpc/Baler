SUBDIRS = . test/

bin_PROGRAMS =
lib_LTLIBRARIES =
AM_CFLAGS = -I@top_srcdir@/src/

AM_YFLAGS = -d
libsyslog_parser_la_SOURCES = syslog_parser.y syslog_lexer.l
libsyslog_parser_la_CFLAGS = $(AM_CFLAGS)
libsyslog_parser_la_LIBADD = ../baler/libbaler.la -ly -ll -lc
# libsyslog_parser_la_LDFLAGS = -g -O0
lib_LTLIBRARIES += libsyslog_parser.la

libbstore_sos_la_SOURCES = bstore_sos.c
libbstore_sos_la_CFLAGS = $(AM_CFLAGS) @SOS_INCDIR_FLAG@
libbstore_sos_la_LIBADD = ../baler/libbaler.la @SOS_LIBDIR_FLAG@ @SOS_LIB64DIR_FLAG@
# libbstore_sos_la_LDFLAGS = -pg -g
lib_LTLIBRARIES += libbstore_sos.la

libbstore_htbl_la_SOURCES = bstore_htbl.c
libbstore_htbl_la_CFLAGS = $(AM_CFLAGS) @SOS_INCDIR_FLAG@
libbstore_htbl_la_LIBADD = ../baler/libbaler.la @SOS_LIBDIR_FLAG@ @SOS_LIB64DIR_FLAG@
# libbstore_htbl_la_LDFLAGS = -pg -g
lib_LTLIBRARIES += libbstore_htbl.la

librsyslog_parser_la_SOURCES = rsyslog_parser.c
librsyslog_parser_la_CFLAGS = $(AM_CFLAGS)
librsyslog_parser_la_LIBADD = ../baler/libbaler.la
lib_LTLIBRARIES += librsyslog_parser.la

libbin_tcp_la_SOURCES = bin_tcp.c
libbin_tcp_la_CFLAGS = $(AM_CFLAGS) @LIBEVENT_INCDIR_FLAG@
libbin_tcp_la_LIBADD = @EVENTLIBS@ -lpthread -ldl ../baler/libbaler.la
lib_LTLIBRARIES += libbin_tcp.la

libbin_udp_la_SOURCES = bin_udp.c
libbin_udp_la_CFLAGS = $(AM_CFLAGS)
libbin_udp_la_LIBADD = -lpthread -ldl ../baler/libbaler.la
lib_LTLIBRARIES += libbin_udp.la

libbin_rsyslog_tcp_la_SOURCES = bin_rsyslog_tcp.c
libbin_rsyslog_tcp_la_CFLAGS = $(AM_CFLAGS) @LIBEVENT_INCDIR_FLAG@
libbin_rsyslog_tcp_la_LIBADD = @EVENTLIBS@ \
			       -lpthread \
			       ../baler/libbaler.la
lib_LTLIBRARIES += libbin_rsyslog_tcp.la

libbin_metric_la_SOURCES = bin_metric.c bin_metric.h
libbin_metric_la_CFLAGS = $(AM_CFLAGS) @LIBEVENT_INCDIR_FLAG@
libbin_metric_la_LIBADD = @EVENTLIBS@ \
			  -lpthread \
			  ../baler/libbaler.la
lib_LTLIBRARIES += libbin_metric.la

libbout_store_msg_la_SOURCES = bout_store_msg.c bout_store_msg.h
libbout_store_msg_la_CFLAGS = $(AM_CFLAGS)
libbout_store_msg_la_LIBADD = ../baler/libbaler.la -lpthread
lib_LTLIBRARIES += libbout_store_msg.la

libbout_store_hist_la_SOURCES = bout_store_hist.c bout_store_hist.h
libbout_store_hist_la_CFLAGS = $(AM_CFLAGS)
libbout_store_hist_la_LIBADD = ../baler/libbaler.la -lpthread
lib_LTLIBRARIES += libbout_store_hist.la

libbout_store_ptn_tkn_la_SOURCES = bout_store_ptn_tkn.c bout_store_ptn_tkn.h
libbout_store_ptn_tkn_la_CFLAGS = $(AM_CFLAGS)
libbout_store_ptn_tkn_la_LIBADD = ../baler/libbaler.la -lpthread
lib_LTLIBRARIES += libbout_store_ptn_tkn.la

libbsos_msg_la_SOURCES = bsos_msg.c bsos_msg.h
libbsos_msg_la_CFLAGS = $(AM_CFLAGS) @SOS_INCDIR_FLAG@
libbsos_msg_la_LIBADD = -lsos -lods ../baler/libbaler.la -lpthread @SOS_LIBDIR_FLAG@ @SOS_LIB64DIR_FLAG@
lib_LTLIBRARIES += libbsos_msg.la

libbsos_img_la_SOURCES = bsos_img.c bsos_img.h
libbsos_img_la_CFLAGS = $(AM_CFLAGS) @SOS_INCDIR_FLAG@
libbsos_img_la_LIBADD = -lsos -lods ../baler/libbaler.la -lpthread @SOS_LIBDIR_FLAG@ @SOS_LIB64DIR_FLAG@
lib_LTLIBRARIES += libbsos_img.la

libbout_sos_la_SOURCES = bout_sos.c bout_sos.h
libbout_sos_la_CFLAGS = $(AM_CFLAGS) @SOS_INCDIR_FLAG@
libbout_sos_la_LIBADD = -lsos -lods ../baler/libbaler.la \
			-lpthread \
			@SOS_LIBDIR_FLAG@ @SOS_LIB64DIR_FLAG@
lib_LTLIBRARIES += libbout_sos.la

libbout_sos_img_la_SOURCES = bout_sos_img.c bout_sos_img.h
libbout_sos_img_la_CFLAGS = $(AM_CFLAGS) @SOS_INCDIR_FLAG@
libbout_sos_img_la_LIBADD = ../baler/libbaler.la \
			    libbout_sos.la \
			    libbsos_img.la \
			    -lpthread \
			    -lsos -lods @SOS_LIBDIR_FLAG@ @SOS_LIB64DIR_FLAG@
lib_LTLIBRARIES += libbout_sos_img.la

libbout_sos_msg_la_SOURCES = bout_sos_msg.c bout_sos_msg.h
libbout_sos_msg_la_CFLAGS = $(AM_CFLAGS) @SOS_INCDIR_FLAG@
libbout_sos_msg_la_LIBADD = ../baler/libbaler.la \
			    libbout_sos.la \
			    libbsos_msg.la \
			    -lpthread \
			    -lsos -lods @SOS_LIBDIR_FLAG@ @SOS_LIB64DIR_FLAG@
lib_LTLIBRARIES += libbout_sos_msg.la

libbout_me_la_SOURCES = bout_me.c
libbout_me_la_CFLAGS = $(AM_CFLAGS) @OVIS_LIB_INCDIR_FLAG@ @LIBEVENT_INCDIR_FLAG@
libbout_me_la_LIBADD = ../baler/libbaler.la \
		       -lpthread -lzap @EVENTLIBS@ @OVIS_LIB_LIBDIR_FLAG@ @OVIS_LIB_LIB64DIR_FLAG@
lib_LTLIBRARIES += libbout_me.la

libbin_test_la_SOURCES = bin_test.c
libbin_test_la_CFLAGS = $(AM_CFLAGS) @OVIS_LIB_INCDIR_FLAG@
libbin_test_la_LIBADD = ../baler/libbaler.la \
			-lpthread @OVIS_LIB_LIBDIR_FLAG@ @OVIS_LIB_LIB64DIR_FLAG@
lib_LTLIBRARIES += libbin_test.la

bsos_part_modify_SOURCES = bsos_part_modify.c
bsos_part_modify_CFLAGS = $(AM_CFLAGS) @SOS_INCDIR_FLAG@
bsos_part_modify_LDADD = ../baler/libbaler.la \
		     -lsos -lods @SOS_LIBDIR_FLAG@ @SOS_LIB64DIR_FLAG@
bin_PROGRAMS += bsos_part_modify
