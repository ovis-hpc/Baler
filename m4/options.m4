dnl SYNOPSIS: OPTION_DEFAULT_ENABLE([name], [enable_flag_var])
dnl EXAMPLE: OPTION_DEFAULT_ENABLE([mysql], [ENABLE_MYSQL])
dnl note: supports hyphenated feature names now.
AC_DEFUN([OPTION_DEFAULT_ENABLE], [
__optenable=
AC_ARG_ENABLE($1, [  --disable-$1	Disable the $1 module],
	[
		if test "x$enableval" = "xno" ; then
			__optenable=no
		else
			__optenable=yes
		fi
	],
	[
		__optenable=yes
	])
AM_CONDITIONAL([$2], [test "x$__optenable" = "xyes"])
])

dnl SYNOPSIS: OPTION_DEFAULT_DISABLE([name], [enable_flag_var])
dnl EXAMPLE: OPTION_DEFAULT_DISABLE([mysql], [ENABLE_MYSQL])
dnl note: supports hyphenated feature names now.
AC_DEFUN([OPTION_DEFAULT_DISABLE], [
__optenable=
AC_ARG_ENABLE($1, [  --enable-$1	Enable the $1 module: $3],
	[
		if test "x$enableval" = "xyes" ; then
			__optenable=yes
		else
			__optenable=no
		fi
	],
	[
		__optenable=no
	])
AM_CONDITIONAL([$2], [test "x$__optenable" = "xyes"])
])

dnl SYNOPSIS: OPTION_WITH([name], [VAR_BASE_NAME])
dnl EXAMPLE: OPTION_WITH([xyz], [XYZ])
dnl NOTE: With VAR_BASE_NAME being XYZ, this macro will set XYZ_INCIDR and
dnl 	XYZ_LIBDIR to the include path and library path respectively.
AC_DEFUN([OPTION_WITH], [
dnl reset withval, or prior option_with uses bleed in here.
withval=""
AC_ARG_WITH(
	$1,
	[AS_HELP_STRING(
		[--with-$1@<:@=path@:>@],
		[Specify $1 path @<:@default=$3@:>@]
	)],
	[
		WITH_$2=$withval
	],
	[
		WITH_$2=$3
	]
)
dnl default the prefix to /usr so that -I<WITH_$2> or -L<WITH_$2> would work
$2_INCDIR=/usr/include
$2_LIBDIR=/usr/lib
$2_LIB64DIR=/usr/lib64
case "x$withval" in
xyes | x/usr | x)
	:
	;;
*)
	if test -d $WITH_$2/lib64; then
		$2_LIB64DIR=$WITH_$2/lib64
		$2_LIB64DIR_FLAG="-L$WITH_$2/lib64"
		LDFLAGS="$LDFLAGS -Wl,-rpath-link=$WITH_$2/lib64"
	fi
	if test -d $WITH_$2/lib; then
		$2_LIBDIR=$WITH_$2/lib
		$2_LIBDIR_FLAG="-L$WITH_$2/lib"
		LDFLAGS="$LDFLAGS -Wl,-rpath-link=$WITH_$2/lib"
	else
		dnl LIBDIR uses lib64/ if lib/ does not present
		$2_LIBDIR=$2_LIB64DIR
		$2_LIBDIR_FLAG=$2_LIB64DIR_FLAG
	fi
	if test -d $WITH_$2/include; then
		$2_INCDIR=$WITH_$2/include
		$2_INCDIR_FLAG=-I$WITH_$2/include
	fi
	;;
esac

AC_SUBST([$2_LIBDIR], [$$2_LIBDIR])
AC_SUBST([$2_LIB64DIR], [$$2_LIB64DIR])
AC_SUBST([$2_INCDIR], [$$2_INCDIR])
AC_SUBST([$2_LIBDIR_FLAG], [$$2_LIBDIR_FLAG])
AC_SUBST([$2_LIB64DIR_FLAG], [$$2_LIB64DIR_FLAG])
AC_SUBST([$2_INCDIR_FLAG], [$$2_INCDIR_FLAG])
]) dnl END OPTION_WITH

dnl SYNOPSIS: OPTION_GITINFO
dnl dnl queries git for version hash and branch info.
dnl export GITSHA and GITTAG variables
AC_DEFUN([OPTION_GITINFO], [
	AC_MSG_CHECKING([git sha])
	GITTAG="$(git describe --tags --always --long 2>/dev/null)"
	GITSHA="$(git rev-parse HEAD 2>/dev/null)"
	GITDIRTY="$(git status -uno -s 2>/dev/null)"
	if test -n "$GITSHA" -a -n "$GITDIRTY"; then
		GITSHA="${GITSHA}-dirty"
		GITTAG="${GITTAG}-dirty"
	fi

	if test -n "$GITSHA"; then
		dnl Git OK from ovis repo.
		AC_MSG_RESULT([using git SHA and TAG])
	elif test -s $srcdir/TAG.txt -a -s $srcdir/SHA.txt ; then
		dnl Git not OK, try $srcdir/SHA.txt
		GITTAG="$(cat $srcdir/TAG.txt)"
		GITSHA="$(cat $srcdir/SHA.txt)"
		AC_MSG_RESULT([using local SHA.txt and TAG.txt])
	else
		GITTAG="NO_GIT_SHA"
		GITSHA=$GITTAG
		AC_MSG_RESULT([NO GIT SHA])
	fi
AC_DEFINE_UNQUOTED([GITSHA],["$GITSHA"],[Hash of last git commit])
AC_DEFINE_UNQUOTED([GITTAG],["$GITTAG"],[Branch and hash mangle of last commit])
AC_SUBST([GITSHA], ["$GITSHA"])
AC_SUBST([GITTAG], ["$GITTAG"])
])

AC_DEFUN([OPTION_DOC_GENERATE],[
if test -z "$ENABLE_DOC_$1_TRUE"
then
	GENERATE_$1=YES
else
	GENERATE_$1=NO
fi
AC_SUBST(GENERATE_$1)
])

dnl For doxygen-based doc
AC_DEFUN([OPTION_DOC],[
	OPTION_DEFAULT_DISABLE([doc], [ENABLE_DOC])
	OPTION_DEFAULT_DISABLE([doc-html], [ENABLE_DOC_HTML])
	OPTION_DEFAULT_DISABLE([doc-latex], [ENABLE_DOC_LATEX])
	OPTION_DEFAULT_ENABLE([doc-man], [ENABLE_DOC_MAN])
	OPTION_DEFAULT_DISABLE([doc-graph], [ENABLE_DOC_GRAPH])
	OPTION_DOC_GENERATE(HTML)
	OPTION_DOC_GENERATE(LATEX)
	OPTION_DOC_GENERATE(MAN)
	OPTION_DOC_GENERATE(GRAPH)
])
