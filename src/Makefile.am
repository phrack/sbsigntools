
bin_PROGRAMS = sbsign sbverify sbattach sbvarsign sbsiglist sbkeysync

coff_headers = coff/external.h coff/pe.h
AM_CFLAGS = -Wall -Wextra --std=gnu99

common_SOURCES = idc.c idc.h image.c image.h fileio.c fileio.h \
	efivars.h $(coff_headers)
common_LDADD = ../lib/ccan/libccan.a $(libcrypto_LIBS)
common_CFLAGS = -I$(top_srcdir)/lib/ccan/ -Werror

sbsign_SOURCES = sbsign.c $(common_SOURCES)
sbsign_LDADD = $(common_LDADD)
sbsign_CFLAGS = $(AM_CFLAGS) $(common_CFLAGS)

sbverify_SOURCES = sbverify.c $(common_SOURCES)
sbverify_LDADD = $(common_LDADD)
sbverify_CFLAGS = $(AM_CFLAGS) $(common_CFLAGS)

sbattach_SOURCES = sbattach.c $(common_SOURCES)
sbattach_LDADD = $(common_LDADD)
sbattach_CFLAGS = $(AM_CFLAGS) $(common_CFLAGS)

sbvarsign_SOURCES = sbvarsign.c $(common_SOURCES)
sbvarsign_LDADD = $(common_LDADD) $(uuid_LIBS)
sbvarsign_CPPFLAGS = $(EFI_CPPFLAGS)
sbvarsign_CFLAGS = $(AM_CFLAGS) $(uuid_CFLAGS) $(common_CFLAGS)

sbsiglist_SOURCES = sbsiglist.c $(common_SOURCES)
sbsiglist_LDADD = $(common_LDADD) $(uuid_LIBS)
sbsiglist_CPPFLAGS = $(EFI_CPPFLAGS)
sbsiglist_CFLAGS = $(AM_CFLAGS) $(common_CFLAGS)

sbkeysync_SOURCES = sbkeysync.c $(common_SOURCES)
sbkeysync_LDADD = $(common_LDADD) $(uuid_LIBS)
sbkeysync_CPPFLAGS = $(EFI_CPPFLAGS)
sbkeysync_CFLAGS = $(AM_CFLAGS) $(common_CFLAGS)
