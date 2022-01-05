/* See LICENSE file for copyright and license details. */
#include "libblake.h"

#include <ctype.h>
#include <inttypes.h>
#include <string.h>

#if !defined(UINT_LEAST32_C) && defined(UINT32_C)
# define UINT_LEAST32_C(X) UINT32_C(X)
#endif

#if !defined(UINT_LEAST64_C) && defined(UINT64_C)
# define UINT_LEAST64_C(X) UINT64_C(X)
#endif

#if defined(__GNUC__)
# define HIDDEN __attribute__((__visibility__("hidden")))
#else
# define HIDDEN
#endif

HIDDEN size_t libblake_internal_blakes_update(struct libblake_blakes_state *state, const unsigned char *data, size_t len);
HIDDEN size_t libblake_internal_blakeb_update(struct libblake_blakeb_state *state, const unsigned char *data, size_t len);

HIDDEN void libblake_internal_blakes_digest(struct libblake_blakes_state *state, unsigned char *data, size_t len,
                                            size_t bits, const char *suffix, unsigned char *output, size_t words_out);
HIDDEN void libblake_internal_blakeb_digest(struct libblake_blakeb_state *state, unsigned char *data, size_t len,
                                            size_t bits, const char *suffix, unsigned char *output, size_t words_out);
