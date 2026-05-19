PREFIX    = /usr
MANPREFIX = $(PREFIX)/share/man

CC = cc -std=c11

COMMON_SANITIZE = -fsanitize=alignment,shift,signed-integer-overflow,object-size,null,undefined,bounds,address
CLANG_SANITIZE  = -O1 $(COMMON_SANITIZE),cfi -flto -fvisibility=hidden -fno-sanitize-trap=cfi
GCC_SANITIZE    = -O1 $(COMMON_SANITIZE)
#SANITIZE        = $(CLANG_SANITIZE)
#SANITIZE        = $(GCC_SANITIZE)

CPPFLAGS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700 -D_GNU_SOURCE
CFLAGS   = $(SANITIZE) -Wall -O3
LDFLAGS  = $(SANITIZE) -s

# These optimisations may not only break compatibility with
# processors that the software was not compiled on, but they
# will in fact also degrade performance. Therefore they are
# only used for specific translation units.
CFLAGS_MM128 = -msse4.1 -mavx2
CFLAGS_MM256 = -msse4.1 -mavx2

DEFAULT_SUPPORT  = yes
SUPPORT_BLAKE1   = $(DEFAULT_SUPPORT)
SUPPORT_BLAKE224 = $(SUPPORT_BLAKE1)
SUPPORT_BLAKE256 = $(SUPPORT_BLAKE1)
SUPPORT_BLAKE384 = $(SUPPORT_BLAKE1)
SUPPORT_BLAKE512 = $(SUPPORT_BLAKE1)
SUPPORT_BLAKE2   = $(DEFAULT_SUPPORT)
SUPPORT_BLAKE2X  = $(SUPPORT_BLAKE2)
SUPPORT_BLAKE2S  = $(SUPPORT_BLAKE2)
SUPPORT_BLAKE2B  = $(SUPPORT_BLAKE2)
SUPPORT_BLAKE2XS = $(SUPPORT_BLAKE2X)
SUPPORT_BLAKE2XB = $(SUPPORT_BLAKE2X)
# Change to "no" (without quotes) to disable.
# SUPPORT_BLAKE2B=yes is needed for libar2
