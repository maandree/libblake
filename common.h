/* See LICENSE file for copyright and license details. */
#include "libblake.h"

#include <ctype.h>
#include <inttypes.h>
#include <string.h>

#if !defined(UINT_LEAST64_C) && defined(UINT64_C)
# define UINT_LEAST64_C(X) UINT64_C(X)
#elif !defined(UINT_LEAST64_C)
# define UINT_LEAST64_C(X) X##ULL
#endif

#if !defined(UINT_LEAST32_C) && defined(UINT32_C)
# define UINT_LEAST32_C(X) UINT32_C(X)
#elif !defined(UINT_LEAST32_C)
# define UINT_LEAST32_C(X) X##UL
#endif

#if !defined(UINT_LEAST16_C) && defined(UINT16_C)
# define UINT_LEAST16_C(X) UINT16_C(X)
#elif !defined(UINT_LEAST16_C)
# define UINT_LEAST16_C(X) X##U
#endif

#if defined(__GNUC__)
# define HIDDEN __attribute__((visibility("hidden")))
# define LIKELY(X) __builtin_expect(!!(X), 1)
# define UNLIKELY(X) __builtin_expect(!!(X), 0)
# define ASSUMING_CONSTANT(X) (__builtin_constant_p(X) && (X))
#else
# define HIDDEN
# define LIKELY(X) X
# define UNLIKELY(X) X
# define ASSUMING_CONSTANT(X) 0
# if defined(__has_builtin)
#  if __has_builtin(__builtin_expect)
#   undef LIKELY
#   undef UNLIKELY
#   define LIKELY(X) __builtin_expect(!!(X), 1)
#   define UNLIKELY(X) __builtin_expect(!!(X), 0)
#  endif
#  if __has_builtin(__builtin_constant_p)
#   undef ASSUMING_CONSTANT
#   define ASSUMING_CONSTANT(X) (__builtin_constant_p(X) && (X))
#  endif
# endif
#endif
#if defined(__has_builtin)
# define HAS_BUILTIN(X) __has_builtin(X)
#else
# define HAS_BUILTIN(X) 0
#endif

#if defined(__x86_64__) || defined(__i386__)
# define LITTLE_ENDIAN
#else
# error Endian is unknown
#endif

#define CODE_KILLER(X) (X)

#define A 10
#define B 11
#define C 12
#define D 13
#define E 14
#define F 15

HIDDEN size_t libblake_internal_blakes_update(struct libblake_blakes_state *state, const unsigned char *data, size_t len);
HIDDEN size_t libblake_internal_blakeb_update(struct libblake_blakeb_state *state, const unsigned char *data, size_t len);

HIDDEN void libblake_internal_blakes_digest(struct libblake_blakes_state *state, unsigned char *data, size_t len,
                                            size_t bits, const char *suffix, unsigned char *output, size_t words_out);
HIDDEN void libblake_internal_blakeb_digest(struct libblake_blakeb_state *state, unsigned char *data, size_t len,
                                            size_t bits, const char *suffix, unsigned char *output, size_t words_out);

HIDDEN void libblake_internal_blake2s_compress(struct libblake_blake2s_state *state, const unsigned char *data);
HIDDEN void libblake_internal_blake2b_compress(struct libblake_blake2b_state *state, const unsigned char *data);
/* HIDDEN void libblake_internal_blake2b_compress_mm128_init(void); */
/* HIDDEN void libblake_internal_blake2b_compress_mm256_init(void); */

HIDDEN void libblake_internal_blake2xs_init0(struct libblake_blake2xs_state *state, const struct libblake_blake2xs_params *params);
HIDDEN void libblake_internal_blake2xb_init0(struct libblake_blake2xb_state *state, const struct libblake_blake2xb_params *params);

HIDDEN void libblake_internal_blake2s_output_digest(struct libblake_blake2s_state *state, size_t output_len, unsigned char *output);
HIDDEN void libblake_internal_blake2b_output_digest(struct libblake_blake2b_state *state, size_t output_len, unsigned char *output);

#if defined(__clang__)
# pragma clang diagnostic ignored "-Wunreachable-code"
# pragma clang diagnostic ignored "-Wvla"
# pragma clang diagnostic ignored "-Wimplicit-fallthrough"
#endif
