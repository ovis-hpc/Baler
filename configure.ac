# NOTE: autoscan can automatically generate configure.ac
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([baler], 4.1.0, narate@ogc.us)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/baler/balerd.c])
AC_CONFIG_AUX_DIR(config)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES],
	 [AM_SILENT_RULES([yes])
])
AM_PROG_LIBTOOL

LT_INIT

dnl AC_PROG_CC_C99()

if test "$ac_cv_prog_cc_c99" = "no"; then
	AC_MSG_ERROR([baler requires a compiler with C99 standard])
fi

AC_PROG_LEX()
AC_PROG_YACC()
AM_PROG_CC_C_O()

OPTION_GITINFO

dnl change sharedstatedir default
test "$sharedstatedir" = '${prefix}/com' && sharedstatedir='${prefix}/var/lib'

OPTION_DEFAULT_ENABLE([dict], [ENABLE_DICT])
OPTION_DEFAULT_DISABLE([etc], [ENABLE_ETC])

OPTION_DEFAULT_ENABLE([python], [ENABLE_PYTHON])
AM_COND_IF([ENABLE_PYTHON], [
	AM_PATH_PYTHON(2.7)
	AX_PYTHON_DEVEL
	AC_PATH_PROG([CYTHON], [cython])
	if test -z "$CYTHON"; then
		AC_MSG_ERROR([baler python module requires cython to build])
	fi
])

dnl ==================================================
dnl == libevent, required
OPTION_DEFAULT_ENABLE([libevent], [ENABLE_LIBEVENT])
OPTION_WITH([libevent], [LIBEVENT])
SAVED_CFLAGS=$CFLAGS
SAVED_LDFLAGS=$LDFLAGS
CFLAGS="$SAVED_CFLAGS $LIBEVENT_INCDIR_FLAG"
LDFLAGS="$SAVED_LDFLAGS $LIBEVENT_LIBDIR_FLAG $LIBEVENT_LIB64DIR_FLAG"
AC_CHECK_HEADER([event2/event.h],
	[],
	[AC_MSG_ERROR([cannot build with libevent header file])]
)
AC_CHECK_LIB([event], [event_base_new],
	[],
	[AC_MSG_ERROR([cannot build with libevent])]
)
CFLAGS=$SAVED_CFLAGS
LDFLAGS=$SAVED_LDFLAGS
LIBS=""
dnl ^^^^^^^^^^^^^^^^ (libevent) ^^^^^^^^^^^^^^^^^^^

dnl ==================================================
dnl == sos, required
OPTION_DEFAULT_ENABLE([sos], [ENABLE_SOS])
OPTION_WITH([sos], [SOS])
AM_COND_IF([ENABLE_SOS],
	[],
	[AC_MSG_ERROR([baler needs sos to build/run])]
)
SAVED_CFLAGS=$CFLAGS
SAVED_LDFLAGS=$LDFLAGS
CFLAGS="$SAVED_CFLAGS $SOS_INCDIR_FLAG"
LDFLAGS="$SAVED_LDFLAGS $SOS_LIBDIR_FLAG $SOS_LIB64DIR_FLAG"
AC_CHECK_HEADER([sos/sos.h],
	[],
	[AC_MSG_ERROR([cannot build with sos header file])]
)
AC_CHECK_LIB([sos], [sos_container_open],
	[],
	[AC_MSG_ERROR([cannot build with libsos])]
)
CFLAGS=$SAVED_CFLAGS
LDFLAGS=$SAVED_LDFLAGS
LIBS=""
dnl ^^^^^^^^^^^^^^^^ (sos) ^^^^^^^^^^^^^^^^^^^


dnl ovis-lib contains zap
OPTION_WITH([ovis-lib], [OVIS_LIB])

dnl ==================================================
dnl == zap, optional
OPTION_DEFAULT_DISABLE([zap], [ENABLE_ZAP])
AM_COND_IF([ENABLE_ZAP], [
	SAVED_CFLAGS=$CFLAGS
	SAVED_LDFLAGS=$LDFLAGS
	CFLAGS="$SAVED_CFLAGS -I$OVIS_LIB_INCDIR"
	LDFLAGS="$SAVED_LDFLAGS -L$OVIS_LIB_LIBDIR"
	AC_CHECK_HEADER([zap/zap.h],
		[],
		[AC_MSG_ERROR([cannot build with zap header file])]
	)
	AC_CHECK_LIB([zap], [zap_get],
		[],
		[AC_MSG_ERROR([cannot build with zap])]
	)
	CFLAGS=$SAVED_CFLAGS
	LDFLAGS=$SAVED_LDFLAGS
	LIBS=""
])
dnl ^^^^^^^^^^^^^^^^ (zap) ^^^^^^^^^^^^^^^^^^^


OPTION_DEFAULT_DISABLE([n2da-test], [ENABLE_N2DA_TEST])

OPTION_DEFAULT_DISABLE([ocm], [ENABLE_OCM])

OPTION_DOC

distdir=${PACKAGE_NAME}-${PACKAGE_VERSION}
AC_SUBST(ac_configure_args)
AC_SUBST(prefix)
AC_SUBST(distdir)

AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])
if test -z "$ENABLE_DOC_TRUE"
then
	AC_CONFIG_FILES([docs/Doxyfile])
fi

AC_CONFIG_FILES([Makefile docs/Makefile src/Makefile
	src/baler/Makefile src/plugins/Makefile
	src/test/Makefile
	src/n2dassoc/Makefile
	src/tools/Makefile
	etc/Makefile
	etc/baler/Makefile
	etc/systemd/Makefile
	dict/Makefile
	python/Makefile
	python/ptn_cmp_ext/Makefile
])

AC_OUTPUT
