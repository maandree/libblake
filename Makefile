.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

OS = linux
# Linux:   linux
# Mac OS:  macos
# Windows: windows
include mk/$(OS).mk


LIB_MAJOR = 3
LIB_MINOR = 0
LIB_VERSION = $(LIB_MAJOR).$(LIB_MINOR)
LIB_NAME = blake


OBJ_BLAKE =\
	libblake_blake224_digest.o\
	libblake_blake224_digest_get_required_input_size.o\
	libblake_blake224_init.o\
	libblake_blake224_init2.o\
	libblake_blake224_update.o\
	libblake_blake256_digest.o\
	libblake_blake256_digest_get_required_input_size.o\
	libblake_blake256_init.o\
	libblake_blake256_init2.o\
	libblake_blake256_update.o\
	libblake_blake384_digest.o\
	libblake_blake384_digest_get_required_input_size.o\
	libblake_blake384_init.o\
	libblake_blake384_init2.o\
	libblake_blake384_update.o\
	libblake_blake512_digest.o\
	libblake_blake512_digest_get_required_input_size.o\
	libblake_blake512_init.o\
	libblake_blake512_init2.o\
	libblake_blake512_update.o\
	libblake_internal_blakeb_digest.o\
	libblake_internal_blakes_digest.o\
	libblake_internal_blakeb_update.o\
	libblake_internal_blakes_update.o

OBJ_BLAKE2 =\
	libblake_blake2b_digest.o\
	libblake_blake2s_digest.o\
	libblake_blake2b_digest_get_required_input_size.o\
	libblake_blake2s_digest_get_required_input_size.o\
	libblake_blake2b_force_update.o\
	libblake_blake2s_force_update.o\
	libblake_blake2b_init.o\
	libblake_blake2s_init.o\
	libblake_blake2b_update.o\
	libblake_blake2s_update.o\
	libblake_blake2xb_digest.o\
	libblake_blake2xs_digest.o\
	libblake_blake2xb_force_update.o\
	libblake_blake2xs_force_update.o\
	libblake_blake2xb_init.o\
	libblake_blake2xs_init.o\
	libblake_blake2xb_predigest.o\
	libblake_blake2xs_predigest.o\
	libblake_blake2xb_predigest_get_required_input_size.o\
	libblake_blake2xs_predigest_get_required_input_size.o\
	libblake_blake2xb_update.o\
	libblake_blake2xs_update.o\
	libblake_internal_blake2b_compress.o\
	libblake_internal_blake2s_compress.o\
	libblake_internal_blake2b_output_digest.o\
	libblake_internal_blake2s_output_digest.o\
	libblake_internal_blake2xb_init0.o\
	libblake_internal_blake2xs_init0.o

OBJ =\
	libblake_encode_hex.o\
	libblake_decode_hex.o\
	libblake_init.o\
	$(OBJ_BLAKE)\
	$(OBJ_BLAKE2)

HDR =\
	libblake.h\
	common.h

# Known answers tests
KAT_FILES =\
	kat-blake2b\
	kat-blake2s

LOBJ = $(OBJ:.o=.lo)


all: libblake.a libblake.$(LIBEXT) test
$(OBJ): $(HDR)
$(LOBJ): $(HDR)
test.o: $(HDR)

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

.c.lo:
	$(CC) -fPIC -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

libblake_internal_blake2b_compress_mm128.o: libblake_internal_blake2b_compress_mm128.c $(HDR)
	$(CC) -c -o $@ $(@:.o=.c) $(CFLAGS) $(CPPFLAGS) $(CFLAGS_MM128)

libblake_internal_blake2b_compress_mm128.lo: libblake_internal_blake2b_compress_mm128.c $(HDR)
	$(CC) -c -o $@ $(@:.lo=.c) $(CFLAGS) $(CPPFLAGS) $(CFLAGS_MM128)

libblake_internal_blake2b_compress_mm256.o: libblake_internal_blake2b_compress_mm256.c $(HDR)
	$(CC) -c -o $@ $(@:.o=.c) $(CFLAGS) $(CPPFLAGS) $(CFLAGS_MM256)

libblake_internal_blake2b_compress_mm256.lo: libblake_internal_blake2b_compress_mm256.c $(HDR)
	$(CC) -c -o $@ $(@:.lo=.c) $(CFLAGS) $(CPPFLAGS) $(CFLAGS_MM256)

test: test.o libblake.a
	$(CC) -o $@ test.o libblake.a $(LDFLAGS)

libblake.a: $(OBJ)
	@rm -f -- $@
	$(AR) rc $@ $(OBJ)

libblake.$(LIBEXT): $(LOBJ)
	$(CC) $(LIBFLAGS) -o $@ $(LOBJ) $(LDFLAGS)

check: test $(KAT_FILES)
	$(CHECK_PREFIX) ./test

install: libblake.a libblake.$(LIBEXT)
	mkdir -p -- "$(DESTDIR)$(PREFIX)/lib"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/include"
	cp -- libblake.a "$(DESTDIR)$(PREFIX)/lib/"
	cp -- libblake.$(LIBEXT) "$(DESTDIR)$(PREFIX)/lib/libblake.$(LIBMINOREXT)"
	$(FIX_INSTALL_NAME) "$(DESTDIR)$(PREFIX)/lib/libblake.$(LIBMINOREXT)"
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
