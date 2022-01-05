/* See LICENSE file for copyright and license details. */
#ifndef LIBBLAKE_H
#define LIBBLAKE_H

#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__)
# define LIBBLAKE_PURE__ __attribute__((__pure__))
#else
# define LIBBLAKE_PURE__
#endif

void libblake_encode_hex(const void *data, size_t n, char out[/* static n * 2 + 1 */], int uppercase);
size_t libblake_decode_hex(const char *data, size_t n, void *out);

#define LIBBLAKE_BLAKE224_OUTPUT_SIZE (224 / 8)
#define LIBBLAKE_BLAKE256_OUTPUT_SIZE (256 / 8)
#define LIBBLAKE_BLAKE384_OUTPUT_SIZE (384 / 8)
#define LIBBLAKE_BLAKE512_OUTPUT_SIZE (512 / 8)

struct libblake_blakes_state {
	uint_least32_t h[8];
	uint_least32_t s[4];
	uint_least32_t t[2];
};

struct libblake_blakeb_state {
	uint_least64_t h[8];
	uint_least64_t s[4];
	uint_least64_t t[2];
};

struct libblake_blake224_state { struct libblake_blakes_state s; };
struct libblake_blake256_state { struct libblake_blakes_state s; };
struct libblake_blake384_state { struct libblake_blakeb_state b; };
struct libblake_blake512_state { struct libblake_blakeb_state b; };

void libblake_blake224_init(struct libblake_blake224_state *state);
size_t libblake_blake224_update(struct libblake_blake224_state *state, const void *data, size_t len);
void libblake_blake224_digest(struct libblake_blake224_state *state, void *data, size_t len, size_t bits,
                              const char *suffix, unsigned char output[static LIBBLAKE_BLAKE224_OUTPUT_SIZE]);
LIBBLAKE_PURE__ size_t libblake_blake224_digest_get_required_input_size(size_t len, size_t bits, const char *suffix);

void libblake_blake256_init(struct libblake_blake256_state *state);
size_t libblake_blake256_update(struct libblake_blake256_state *state, const void *data, size_t len);
void libblake_blake256_digest(struct libblake_blake256_state *state, void *data, size_t len, size_t bits,
                              const char *suffix, unsigned char output[static LIBBLAKE_BLAKE256_OUTPUT_SIZE]);
LIBBLAKE_PURE__ size_t libblake_blake256_digest_get_required_input_size(size_t len, size_t bits, const char *suffix);

void libblake_blake384_init(struct libblake_blake384_state *state);
size_t libblake_blake384_update(struct libblake_blake384_state *state, const void *data, size_t len);
void libblake_blake384_digest(struct libblake_blake384_state *state, void *data, size_t len, size_t bits,
                              const char *suffix, unsigned char output[static LIBBLAKE_BLAKE384_OUTPUT_SIZE]);
LIBBLAKE_PURE__ size_t libblake_blake384_digest_get_required_input_size(size_t len, size_t bits, const char *suffix);

void libblake_blake512_init(struct libblake_blake512_state *state);
size_t libblake_blake512_update(struct libblake_blake512_state *state, const void *data, size_t len);
void libblake_blake512_digest(struct libblake_blake512_state *state, void *data, size_t len, size_t bits,
                              const char *suffix, unsigned char output[static LIBBLAKE_BLAKE512_OUTPUT_SIZE]);
LIBBLAKE_PURE__ size_t libblake_blake512_digest_get_required_input_size(size_t len, size_t bits, const char *suffix);

#endif
