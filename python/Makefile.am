SUBDIRS = ptn_cmp_ext

CFLAGS := $(filter-out -Werror, ${CFLAGS})

pkgpython_PYTHON = __init__.py ptn_order.py util.py \
		   named2darray.py
pkgpyexec_LTLIBRARIES = Bq.la
Bq_la_SOURCES = Bq.pyx Bs.pxd
nodist_Bq_la_SOURCES = Bq.c
Bq_la_CFLAGS = -g -O0 -I$(top_srcdir) $(PYTHON_CPPFLAGS) \
	-I$(top_srcdir)/src \
	-I/usr/local/lib/python2.7/dist-packages/numpy/core/include
Bq_la_LDFLAGS = $(PYTHON_LDFLAGS) -module -shared
Bq_la_LIBADD = $(top_builddir)/src/baler/libbaler.la

pkgpyexecdir = $(pkgpythondir)

Bq.c: Bq.pyx Bs.pxd
	$(CYTHON) --gdb $< -o $@

dist_bin_SCRIPTS = bq bclient n2daplot

clean-local:
	rm -f Bq.c
