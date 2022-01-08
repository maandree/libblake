/* See LICENSE file for copyright and license details. */
#ifndef LIBBLAKE_H
#define LIBBLAKE_H

#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__)
# define LIBBLAKE_PURE__ __attribute__((__pure__))
# define LIBBLAKE_CONST__ __attribute__((__const__))
#else
# define LIBBLAKE_PURE__
# define LIBBLAKE_CONST__
#endif


void libblake_encode_hex(const void *data, size_t n, char out[/* static n * 2 + 1 */], int uppercase);
size_t libblake_decode_hex(const char *data, size_t n, void *out, int *validp);


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
void libblake_blake224_init2(struct libblake_blake224_state *state, uint_least8_t salt[16]);
size_t libblake_blake224_update(struct libblake_blake224_state *state, const void *data, size_t len);
void libblake_blake224_digest(struct libblake_blake224_state *state, void *data, size_t len, size_t bits,
                              const char *suffix, unsigned char output[static LIBBLAKE_BLAKE224_OUTPUT_SIZE]);
LIBBLAKE_PURE__ size_t libblake_blake224_digest_get_required_input_size(size_t len, size_t bits, const char *suffix);

void libblake_blake256_init(struct libblake_blake256_state *state);
void libblake_blake256_init2(struct libblake_blake256_state *state, uint_least8_t salt[16]);
size_t libblake_blake256_update(struct libblake_blake256_state *state, const void *data, size_t len);
void libblake_blake256_digest(struct libblake_blake256_state *state, void *data, size_t len, size_t bits,
                              const char *suffix, unsigned char output[static LIBBLAKE_BLAKE256_OUTPUT_SIZE]);
LIBBLAKE_PURE__ size_t libblake_blake256_digest_get_required_input_size(size_t len, size_t bits, const char *suffix);

void libblake_blake384_init(struct libblake_blake384_state *state);
void libblake_blake384_init2(struct libblake_blake384_state *state, uint_least8_t salt[32]);
size_t libblake_blake384_update(struct libblake_blake384_state *state, const void *data, size_t len);
void libblake_blake384_digest(struct libblake_blake384_state *state, void *data, size_t len, size_t bits,
                              const char *suffix, unsigned char output[static LIBBLAKE_BLAKE384_OUTPUT_SIZE]);
LIBBLAKE_PURE__ size_t libblake_blake384_digest_get_required_input_size(size_t len, size_t bits, const char *suffix);

void libblake_blake512_init(struct libblake_blake512_state *state);
void libblake_blake512_init2(struct libblake_blake512_state *state, uint_least8_t salt[32]);
size_t libblake_blake512_update(struct libblake_blake512_state *state, const void *data, size_t len);
void libblake_blake512_digest(struct libblake_blake512_state *state, void *data, size_t len, size_t bits,
                              const char *suffix, unsigned char output[static LIBBLAKE_BLAKE512_OUTPUT_SIZE]);
LIBBLAKE_PURE__ size_t libblake_blake512_digest_get_required_input_size(size_t len, size_t bits, const char *suffix);


struct libblake_blake2s_params {
	uint_least8_t digest_len; /* in bytes, [1, 32] */
	uint_least8_t key_len; /* in bytes, [0, 32] */
	uint_least8_t fanout; /* normally 1 */
	uint_least8_t depth; /* normally 1 */
	uint_least32_t leaf_len; /* normally 0 */
	uint_least32_t node_offset; /* normally 0 */
	uint_least16_t xof_len; /* normally 0 */
	uint_least8_t node_depth; /* normally 0 */
	uint_least8_t inner_len; /* normally 0 */
	uint_least8_t salt[8];
	uint_least8_t pepper[8];
};

struct libblake_blake2b_params {
	uint_least8_t digest_len; /* in bytes, [1, 64] */
	uint_least8_t key_len; /* in bytes, [0, 64] */
	uint_least8_t fanout; /* normally 1 */
	uint_least8_t depth; /* normally 1 */
	uint_least32_t leaf_len; /* normally 0 */
	uint_least32_t node_offset; /* normally 0 */
	uint_least32_t xof_len; /* normally 0 */
	uint_least8_t node_depth; /* normally 0 */
	uint_least8_t inner_len; /* normally 0 */
	uint_least8_t salt[16];
	uint_least8_t pepper[16];
};

struct libblake_blake2s_state {
	uint_least32_t h[8];
	uint_least32_t t[2];
	uint_least32_t f[2];
};

struct libblake_blake2b_state {
	uint_least64_t h[8];
	uint_least64_t t[2];
	uint_least64_t f[2];
};

void libblake_blake2s_init(struct libblake_blake2s_state *state, const struct libblake_blake2s_params *params,
                           const unsigned char *key /* append null bytes until 64 bytes; if key is used */);
size_t libblake_blake2s_update(struct libblake_blake2s_state *state, const void *data, size_t len);
void libblake_blake2s_digest(struct libblake_blake2s_state *state, void *data, size_t len, int last_node /* normally 0 */,
                             size_t output_len, unsigned char output[static output_len]);
LIBBLAKE_CONST__ size_t libblake_blake2s_digest_get_required_input_size(size_t len);

void libblake_blake2b_init(struct libblake_blake2b_state *state, const struct libblake_blake2b_params *params,
                           const unsigned char *key /* append null bytes until 128 bytes; if key is used */);
size_t libblake_blake2b_update(struct libblake_blake2b_state *state, const void *data, size_t len);
void libblake_blake2b_digest(struct libblake_blake2b_state *state, void *data, size_t len, int last_node /* normally 0 */,
                             size_t output_len, unsigned char output[static output_len]);
LIBBLAKE_CONST__ size_t libblake_blake2b_digest_get_required_input_size(size_t len);

#endif
