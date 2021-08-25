
man1_MANS = sbsign.1 sbverify.1 sbattach.1 sbvarsign.1 sbsiglist.1 \
		sbkeysync.1

EXTRA_DIST = sbsign.1.in sbverify.1.in sbattach.1.in \
		sbvarsign.1.in sbsiglist.1.in sbkeysync.1.in
CLEANFILES = $(man1_MANS)

$(builddir)/%.1: $(srcdir)/%.1.in $(top_builddir)/src/%
	$(MKDIR_P) $(@D)
	$(HELP2MAN) --no-info -i $< -o $@ $(top_builddir)/src/$*

