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


OBJ_COMMON =\
	libblake_encode_hex.o\
	libblake_decode_hex.o\
	libblake_init.o

CPPFLAGS_SUPPORT =\
	$(CPPFLAGS_BLAKE224)\
	$(CPPFLAGS_BLAKE256)\
	$(CPPFLAGS_BLAKE384)\
	$(CPPFLAGS_BLAKE512)\
	$(CPPFLAGS_BLAKE2S)\
	$(CPPFLAGS_BLAKE2B)\
	$(CPPFLAGS_BLAKE2XS)\
	$(CPPFLAGS_BLAKE2XB)

OBJ =\
	$(OBJ_COMMON)\
	$(OBJ_BLAKE224)\
	$(OBJ_BLAKE256)\
	$(OBJ_BLAKES)\
	$(OBJ_BLAKE384)\
	$(OBJ_BLAKE512)\
	$(OBJ_BLAKEB)\
	$(OBJ_BLAKE2S)\
	$(OBJ_BLAKE2XS)\
	$(OBJ_BLAKE2S_2XS)\
	$(OBJ_BLAKE2B)\
	$(OBJ_BLAKE2XB)\
	$(OBJ_BLAKE2B_2XB)

HDR =\
	libblake.h\
	common.h

SRC =\
	$(OBJ:.o=.c)\
	$(HDR)\
	test.c

# Known answers tests
KAT_FILES =\
	kat/blake2b\
	kat/blake2s\
	kat/blake2xb\
	kat/blake2xs

LOBJ = $(OBJ:.o=.lo)


include mk/support-blake224=$(SUPPORT_BLAKE224).mk
include mk/support-blake256=$(SUPPORT_BLAKE256).mk
include mk/support-blake384=$(SUPPORT_BLAKE384).mk
include mk/support-blake512=$(SUPPORT_BLAKE512).mk
include mk/support-blake2s=$(SUPPORT_BLAKE2S).mk
include mk/support-blake2b=$(SUPPORT_BLAKE2B).mk
include mk/support-blake2xs=$(SUPPORT_BLAKE2XS).mk
include mk/support-blake2xb=$(SUPPORT_BLAKE2XB).mk


all: libblake.a libblake.$(LIBEXT) test
	@printf '\n' 2>&1
	@printf '%s support: %s\n' 2>&1 \
		BLAKE224 $(SUPPORT_BLAKE224)\
		BLAKE245 $(SUPPORT_BLAKE256)\
		BLAKE384 $(SUPPORT_BLAKE384)\
		BLAKE512 $(SUPPORT_BLAKE512)\
		BLAKE2S $(SUPPORT_BLAKE2S)\
		BLAKE2B $(SUPPORT_BLAKE2B)\
		BLAKE2XS $(SUPPORT_BLAKE2XS)\
		BLAKE2XB $(SUPPORT_BLAKE2XB)

$(OBJ): $(HDR)
$(LOBJ): $(HDR)
test.o: $(HDR)

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS) $(CPPFLAGS_SUPPORT)

.c.lo:
	$(CC) -fPIC -c -o $@ $< $(CFLAGS) $(CPPFLAGS) $(CPPFLAGS_SUPPORT)

libblake_internal_blake2b_compress_mm128.o: libblake_internal_blake2b_compress_mm128.c $(HDR)
	$(CC) -c -o $@ $(@:.o=.c) $(CFLAGS) $(CPPFLAGS) $(CPPFLAGS_SUPPORT) $(CFLAGS_MM128)

libblake_internal_blake2b_compress_mm128.lo: libblake_internal_blake2b_compress_mm128.c $(HDR)
	$(CC) -c -o $@ $(@:.lo=.c) $(CFLAGS) $(CPPFLAGS) $(CPPFLAGS_SUPPORT) $(CFLAGS_MM128)

libblake_internal_blake2b_compress_mm256.o: libblake_internal_blake2b_compress_mm256.c $(HDR)
	$(CC) -c -o $@ $(@:.o=.c) $(CFLAGS) $(CPPFLAGS) $(CPPFLAGS_SUPPORT) $(CFLAGS_MM256)

libblake_internal_blake2b_compress_mm256.lo: libblake_internal_blake2b_compress_mm256.c $(HDR)
	$(CC) -c -o $@ $(@:.lo=.c) $(CFLAGS) $(CPPFLAGS) $(CPPFLAGS_SUPPORT) $(CFLAGS_MM256)

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
