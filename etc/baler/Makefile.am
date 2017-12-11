ACLOCAL_AMFLAGS = -I m4

CONF_DIR = $(DESTDIR)$(sysconfdir)/baler

do_subst = sed -e 's,[@]datadir[@],$(datadir),g' \
	   -e 's,[@]localstatedir[@],$(localstatedir),g' \
	   -e 's,[@]sysconfdir[@],$(sysconfdir),g' \
	   -e 's,[@]sharedstatedir[@],$(sharedstatedir),g' \
	   -e 's,[@]ZAP_LIBPATH[@],$(ZAP_LIBPATH),g' \
	   -e 's,[@]sbindir[@],$(sbindir),g' \
	   -e 's,[@]bindir[@],$(bindir),g' \
	   -e 's,[@]libdir[@],$(libdir),g' \
	   -e 's,[@]pythondir[@],$(pythondir),g' \
	   -e 's,[@]SOS_LIBDIR[@],$(SOS_LIBDIR),g' \
	   -e 's,[@]SOS_LIB64DIR[@],$(SOS_LIB64DIR),g' 

EXTRA_DIST = balerd.conf.in \
	     balerd.env.in \
	     baler-env.sh.in \
	     hosts.txt

ENV_FILES = balerd.env

CONF_FILES = balerd.conf

SH_FILES = baler-env.sh 

# rules to generate env file
%.env: $(srcdir)/%.env.in
	$(do_subst) < $< > $@

# rules for conf file
%.conf: $(srcdir)/%.conf.in
	$(do_subst) < $< > $@

%.sh: $(srcdir)/%.sh.in
	$(do_subst) < $< > $@

install-data-local: $(ENV_FILES) $(CONF_FILES) $(SH_FILES)
	$(MKDIR_P) $(CONF_DIR)
	$(INSTALL_DATA) $(ENV_FILES) $(CONF_FILES) $(SH_FILES) $(CONF_DIR)
	$(INSTALL_DATA) $(srcdir)/hosts.txt $(CONF_DIR)

uninstall-local:
	cd $(CONF_DIR) && rm -f $(ENV_FILES) $(CONF_FILES) $(SH_FILES) hosts.txt
