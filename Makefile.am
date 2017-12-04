EXTRA_DIST = SHA.txt TAG.txt

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src

if ENABLE_PYTHON
SUBDIRS += python
endif

if ENABLE_ETC
SUBDIRS += etc
endif

if ENABLE_DICT
SUBDIRS += dict
endif

if ENABLE_DOC
SUBDIRS += docs
endif
