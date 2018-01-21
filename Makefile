prefix=/usr
DESTDIR=
TPROOT=/var/lib/teapotnet

CC=$(CROSS)gcc
CXX=$(CROSS)g++
RM=rm -f
CCFLAGS=-O2 -fno-var-tracking
CPPFLAGS=-pthread -std=c++14 -Wall -Wno-sign-compare -O2 -fno-var-tracking
LDFLAGS=-pthread
LDLIBS=-ldl -lnettle -lhogweed -lgmp -lgnutls -largon2

SRCS=$(shell printf "%s " pla/*.cpp tpn/*.cpp)
OBJS=$(subst .cpp,.o,$(SRCS))

all: teapotnet

include/sqlite3.o: include/sqlite3.c
	$(CC) $(CCFLAGS) -I. -DSQLITE_ENABLE_FTS3 -DSQLITE_ENABLE_FTS3_PARENTHESIS -o $*.o -c $*.c

%.o: %.cpp
	$(CXX) $(CPPFLAGS) -I. -MMD -MP -o $@ -c $<

-include $(subst .o,.d,$(OBJS))

teapotnet: librtcdcpp/librtcdcpp.a $(OBJS) include/sqlite3.o
	$(CXX) $(LDFLAGS) -o teapotnet $(OBJS) include/sqlite3.o librtcdcpp/librtcdcpp.a $(LDLIBS)

librtcdcpp/librtcdcpp.a: 
	cd librtcdcpp && $(MAKE)

clean:
	$(RM) include/*.o pla/*.o pla/*.d tpn/*.o tpn/*.d

dist-clean: clean
	$(RM) teapotnet
	$(RM) pla/*~ tpn/*~

install: teapotnet teapotnet.service
	install -d $(DESTDIR)$(prefix)/bin
	install -d $(DESTDIR)/etc
	install -d $(DESTDIR)$(prefix)/share/teapotnet
	install -m 0755 teapotnet $(DESTDIR)$(prefix)/bin
	cp -r static $(DESTDIR)$(prefix)/share/teapotnet
	echo "static_dir=$(prefix)/share/teapotnet/static" > $(DESTDIR)/etc/teapotnet.conf
	@if [ -z "$(DESTDIR)" ]; then bash -c "./daemon.sh install $(prefix) $(TPROOT)"; fi

uninstall:
	rm -f $(DESTDIR)$(prefix)/bin/teapotnet
	rm -rf $(DESTDIR)$(prefix)/share/teapotnet
	rm -f $(DESTDIR)/etc/teapotnet.conf
	@if [ -z "$(DESTDIR)" ]; then bash -c "./daemon.sh uninstall $(prefix) $(TPROOT)"; fi
