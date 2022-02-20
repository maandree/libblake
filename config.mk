PREFIX    = /usr
MANPREFIX = $(PREFIX)/share/man

CC = cc -std=c11

CPPFLAGS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700 -D_GNU_SOURCE
#CFLAGS   = -Wall -O3
#LDFLAGS  = -s
CFLAGS   = -Wall -Og -g
LDFLAGS  = 

# These optimisations may not only break compatibility with
# processors that the software was not compiled on, but they
# will infact also degrade performance. Therefore they are
# only only used for specific translation units.
CFLAGS_MM128 = -msse4.1 -mavx2
CFLAGS_MM256 = -msse4.1 -mavx2
