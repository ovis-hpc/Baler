AM_CFLAGS = -D_GNU_SOURCE
#AM_LDFLAGS =

lib_LTLIBRARIES =
bin_PROGRAMS =
sbin_PROGRAMS =

# A library for Baler-specific work functions, also includes codes from
# dependent libraries so that the build on Ubuntu is easier (no need to specify
# all libraries).
libbaler_la_SOURCES = mq.c bwqueue.c btkn.c bptn.c binput.c boutput.c \
		      bmapper.c bset.c bmvec.c bmem.c butils.c bhash.c \
		      bhash_u.c \
		      bstore.c \
		      bmhash.c \
		      bheap.c \
		      bqueue.c \
		      bmqueue.c \
		      binput_private.h \
		      fnv_hash.h \
		      murmur_hash.h
libbaler_la_LDFLAGS = $(AM_LDFLAGS) -lpthread -lsos -ldl -lcoll \
		      @OVIS_LIB_LIBDIR_FLAG@
libbaler_la_CFLAGS = $(AM_CFLAGS) \
	@OVIS_LIB_INCDIR_FLAG@ @SOS_INCDIR_FLAG@ \
	@SOS_LIBDIR_FLAG@ @SOS_LIB64DIR_FLAG@
lib_LTLIBRARIES += libbaler.la

balerd_SOURCES = balerd.c
balerd_LDADD = libbaler.la \
	       -lcoll -levent -levent_pthreads -lzap -lpthread -ldl
balerd_CFLAGS = $(AM_CFLAGS) @OVIS_LIB_INCDIR_FLAG@ @LIBEVENT_INCDIR_FLAG@
#balerd_CFLAGS = -pg @OVIS_LIB_INCDIR_FLAG@ @LIBEVENT_INCDIR_FLAG@
balerd_LDFLAGS = @OVIS_LIB_LIBDIR_FLAG@ @OVIS_LIB_LIB64DIR_FLAG@ @EVENTLIBS@

pit_SOURCES = pit.c
pit_LDADD = libbaler.la -ldl

if ENABLE_OCM
balerd_LDADD += -locm
balerd_CFLAGS += -DENABLE_OCM @OCM_INCDIR_FLAG@
balerd_LDFLAGS += @OCM_LIBDIR_FLAG@
endif
bin_PROGRAMS += balerd pit

bmap_dump_SOURCES = bmap_dump.c
bmap_dump_LDADD = libbaler.la
bin_PROGRAMS += bmap_dump

pkginclude_HEADERS = barray.h \
		     bcommon.h \
		     bhash.h \
		     bhash_u.h \
		     bheap.h \
		     bstore.h \
		     binput.h \
		     bmapper.h \
		     bmem.h \
		     bmhash.h \
		     bmlist.h \
		     bmlist2.h \
		     bmvec.h \
		     boutput.h \
		     bplugin.h \
		     bptn.h \
		     bqueue.h \
		     bmqueue.h \
		     bset.h \
		     btkn.h \
		     btkn_types.h \
		     btypes.h \
		     butils.h \
		     bwqueue.h \
		     mq.h
