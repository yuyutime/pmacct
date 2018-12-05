WEB_CFLAGS = -DMG_ENABLE_THREADS -DMG_ENABLE_HTTP_WEBSOCKET=0
AM_CFLAGS = $(PMACCT_CFLAGS) $(WEB_CFLAGS)
noinst_LTLIBRARIES = libweb.la
libweb_la_SOURCES =  web.h web.c web_handlers.c mongoose.h mongoose.c
libweb_la_CFLAGS = -I$(srcdir)/.. $(AM_CFLAGS)
