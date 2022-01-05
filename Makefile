.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

OS = linux
# Linux:   linux
# Mac OS:  macos
# Windows: windows
include mk/$(OS).mk


LIB_MAJOR = 1
LIB_MINOR = 0
LIB_VERSION = $(LIB_MAJOR).$(LIB_MINOR)
LIB_NAME = blake


OBJ_BLAKE =\
	libblake_blake224_digest.o\
	libblake_blake224_digest_get_required_input_size.o\
	libblake_blake224_init.o\
	libblake_blake224_update.o\
	libblake_blake256_digest.o\
	libblake_blake256_digest_get_required_input_size.o\
	libblake_blake256_init.o\
	libblake_blake256_update.o\
	libblake_blake384_digest.o\
	libblake_blake384_digest_get_required_input_size.o\
	libblake_blake384_init.o\
	libblake_blake384_update.o\
	libblake_blake512_digest.o\
	libblake_blake512_digest_get_required_input_size.o\
	libblake_blake512_init.o\
	libblake_blake512_update.o\
	libblake_internal_blakeb_digest.o\
	libblake_internal_blakes_digest.o\
	libblake_internal_blakeb_update.o\
	libblake_internal_blakes_update.o

OBJ =\
	libblake_encode_hex.o\
	libblake_decode_hex.o\
	$(OBJ_BLAKE)

HDR =\
	libblake.h

LOBJ = $(OBJ:.o=.lo)


all: libblake.a libblake.$(LIBEXT) test
$(OBJ): $(HDR)
$(LOBJ): $(HDR)

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

.c.lo:
	$(CC) -fPIC -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

test: test.o libblake.a
	$(CC) -o $@ test.o libblake.a $(LDFLAGS)

libblake.a: $(OBJ)
	@rm -f -- $@
	$(AR) rc $@ $(OBJ)

libblake.$(LIBEXT): $(LOBJ)
	$(CC) $(LIBFLAGS) -o $@ $(LOBJ) $(LDFLAGS)

check: test
	$(CHECK_PREFIX) ./test

install: libblake.a libblake.$(LIBEXT)
	mkdir -p -- "$(DESTDIR)$(PREFIX)/lib"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/include"
	cp -- libblake.a "$(DESTDIR)$(PREFIX)/lib/"
	cp -- libblake.$(LIBEXT) "$(DESTDIR)$(PREFIX)/lib/libblake.$(LIBMINOREXT)"
	ln -sf -- libblake.$(LIBMINOREXT) "$(DESTDIR)$(PREFIX)/lib/libblake.$(LIBMAJOREXT)"
	ln -sf -- libblake.$(LIBMAJOREXT) "$(DESTDIR)$(PREFIX)/lib/libblake.$(LIBEXT)"
	cp -- libblake.h "$(DESTDIR)$(PREFIX)/include/"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libblake.a"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libblake.$(LIBMAJOREXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libblake.$(LIBMINOREXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libblake.$(LIBEXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/include/libblake.h"

clean:
	-rm -f -- *.o *.a *.lo *.su *.so *.so.* *.dll *.dylib
	-rm -f -- *.gch *.gcov *.gcno *.gcda *.$(LIBEXT) test

.SUFFIXES:
.SUFFIXES: .lo .o .c

.PHONY: all check install uninstall clean