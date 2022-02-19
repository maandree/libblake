/* See LICENSE file for copyright and license details. */
#ifndef LIBBLAKE_H
#define LIBBLAKE_H

#include <stddef.h>
#include <stdint.h>

#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wpadded"
# pragma clang diagnostic ignored "-Wvla"
#endif

#ifndef LIBBLAKE_PUBLIC__
# if defined(_MSC_VER)
#  define LIBBLAKE_PUBLIC__ __declspec(dllexport)
# else
#  define LIBBLAKE_PUBLIC__
# endif
#endif

#if defined(__GNUC__)
# define LIBBLAKE_PURE__ __attribute__((__pure__))
# define LIBBLAKE_CONST__ __attribute__((__const__))
#else
# define LIBBLAKE_PURE__
# define LIBBLAKE_CONST__
#endif

#if defined(__STDC_VERSION__)
# if __STDC_VERSION__ >= 201112L
#  define LIBBLAKE_ALIGNED__(BYTES) _Alignas(BYTES)
# endif
#endif
#ifndef LIBBLAKE_ALIGNED__
# if defined(__GNUC__)
#  define LIBBLAKE_ALIGNED__(BYTES) __attribute__((__aligned__(BYTES)))
# else
#  define LIBBLAKE_ALIGNED__(BYTES)
# endif
#endif



/**
 * Initialise the library
 */
LIBBLAKE_PUBLIC__ void
libblake_init(void);


/**
 * Encode binary data to hexadecimal
 * 
 * @param  data       The binary data to encode
 * @param  n          The number of bytes to encode
 * @param  out        Output buffer for the hexadecimal representation,
 *                    must fit at least `2 * n` characters plus a NUL byte
 * @param  uppercase  If non-zero, the output will be in upper case,
 *                    if zero, the output will be in lower case
 */
LIBBLAKE_PUBLIC__ void
libblake_encode_hex(const void *data, size_t n, char out[/* static n * 2 + 1 */], int uppercase);

/**
 * Decode binary data from hexadecimal
 * 
 * @param   data    The hexadecimal data to decode
 * @param   n       The maximum number of bytes to read from `data`;
 *                  the function will stop reading when a NUL byte is
 *                  encountered, even if `n` bytes have not been read
 * @param   out     Output buffer for the binary data, or `NULL`
 * @param   validp  Will be set to 0 if a byte that was not part of
 *                  the encoding was encountered, and to 1 otherwise;
 *                  must not be `NULL`
 * @return          The number of bytes written to `out`, or that
 *                  would be written (if `out` is `NULL`)
 */
LIBBLAKE_PUBLIC__ size_t
libblake_decode_hex(const char *data, size_t n, void *out, int *validp);



/*********************************** BLAKE ***********************************/

/**
 * The hash size, in bytes, for BLAKE224
 */
#define LIBBLAKE_BLAKE224_OUTPUT_SIZE (224 / 8)

/**
 * The hash size, in bytes, for BLAKE256
 */
#define LIBBLAKE_BLAKE256_OUTPUT_SIZE (256 / 8)

/**
 * The hash size, in bytes, for BLAKE384
 */
#define LIBBLAKE_BLAKE384_OUTPUT_SIZE (384 / 8)

/**
 * The hash size, in bytes, for BLAKE512
 */
#define LIBBLAKE_BLAKE512_OUTPUT_SIZE (512 / 8)

/**
 * State for BLAKEs hashing (BLAKE224 and BLAKE256)
 * 
 * This structure should be considered internal
 */
struct libblake_blakes_state {
	uint_least32_t h[8];
	uint_least32_t s[4];
	uint_least32_t t[2];
};

/**
 * State for BLAKEb hashing (BLAKE384 and BLAKE512)
 * 
 * This structure should be considered internal
 */
struct libblake_blakeb_state {
	uint_least64_t h[8];
	uint_least64_t s[4];
	uint_least64_t t[2];
};

/**
 * State for BLAKE224 hashing
 * 
 * This structure should be opaque
 */
struct libblake_blake224_state { struct libblake_blakes_state s; };

/**
 * State for BLAKE256 hashing
 * 
 * This structure should be opaque
 */
struct libblake_blake256_state { struct libblake_blakes_state s; };

/**
 * State for BLAKE384 hashing
 * 
 * This structure should be opaque
 */
struct libblake_blake384_state { struct libblake_blakeb_state b; };

/**
 * State for BLAKE512 hashing
 * 
 * This structure should be opaque
 */
struct libblake_blake512_state { struct libblake_blakeb_state b; };



/**
 * Initialise a state for hashing with BLAKE224
 * 
 * @param  state  The state to initialise
 * @param  salt   16-byte salt to use, or `NULL` for an all-zeroes salt
 */
LIBBLAKE_PUBLIC__ void
libblake_blake224_init2(struct libblake_blake224_state *state, const uint_least8_t salt[16]);

/**
 * Initialise a state for hashing with BLAKE224
 * and an all-zeroes salt
 * 
 * @param  state  The state to initialise
 */
LIBBLAKE_PUBLIC__ inline void
libblake_blake224_init(struct libblake_blake224_state *state) {
	libblake_blake224_init2(state, NULL);
}

/**
 * Process data for hashing with BLAKE224
 * 
 * The function can process multiples of 64 bytes,
 * any data in excess of a 64-byte multiple will be
 * ignored and must be processed when more data is
 * available or using `libblake_blake224_digest`
 * when the end of the input has been reached
 * 
 * @param   state  The state of the hash function
 * @param   data   The data to feed into the function
 * @param   len    The maximum number of bytes to process
 * @return         The number of processed bytes
 */
LIBBLAKE_PUBLIC__ size_t
libblake_blake224_update(struct libblake_blake224_state *state, const void *data, size_t len);

/**
 * Get the required allocation size of the
 * input buffer for `libblake_blake224_digest`
 * 
 * @param   len     The number of input whole bytes
 * @param   bits    The number of input bits after the last whole bytes
 *                  (may actually be greater than 7)
 * @param   suffix  String of '0's and '1's of addition bits to add to the
 *                  end of the input, or `NULL` (or the empty string) if none
 * @return          The number bytes required for the input buffer
 */
LIBBLAKE_PUBLIC__ LIBBLAKE_PURE__ size_t
libblake_blake224_digest_get_required_input_size(size_t len, size_t bits, const char *suffix);

/**
 * Calculate the input a BLAKE224 hash
 * 
 * The `state` parameter must be initialised using the
 * `libblake_blake224_init` function, after which, but
 * before this function is called, `libblake_blake224_update`
 * can be used to process data before this function is
 * called. Already processed data shall not be input to
 * this function.
 * 
 * @param  state   The state of the hash function
 * @param  data    Data to process; the function will write addition data to
 *                 the end, therefore the size of this buffer must be at least
 *                 `libblake_blake224_digest_get_required_input_size(len, bits, suffix)`
 *                 bytes large
 * @param  len     The number of input whole bytes
 * @param  bits    The number of input bits after the last whole bytes
 *                 (may actually be greater than 7); these bits shall
 *                 be stored in `data[len]`'s (addition bytes will be used
 *                 if `bits > 8`) lower bits
 * @param  suffix  String of '0's and '1's of addition bits to add to the
 *                 end of the input, or `NULL` (or the empty string) if none;
 *                 the first character corresponds to the lowest indexed
 *                 additional bit, and the last character corresponds to
 *                 the highest indexed additional bit
 * @param  output  Output buffer for the hash, which will be stored in raw
 *                 binary representation; the size of this buffer must be
 *                 at least `LIBBLAKE_BLAKE224_OUTPUT_SIZE` bytes
 */
LIBBLAKE_PUBLIC__ void
libblake_blake224_digest(struct libblake_blake224_state *state, void *data, size_t len, size_t bits,
                         const char *suffix, unsigned char output[static LIBBLAKE_BLAKE224_OUTPUT_SIZE]);



/**
 * Initialise a state for hashing with BLAKE256
 * 
 * @param  state  The state to initialise
 * @param  salt   16-byte salt to use, or `NULL` for an all-zeroes salt
 */
LIBBLAKE_PUBLIC__ void
libblake_blake256_init2(struct libblake_blake256_state *state, const uint_least8_t salt[16]);

/**
 * Initialise a state for hashing with BLAKE256
 * and an all-zeroes salt
 * 
 * @param  state  The state to initialise
 */
LIBBLAKE_PUBLIC__ inline void
libblake_blake256_init(struct libblake_blake256_state *state) {
	libblake_blake256_init2(state, NULL);
}

/**
 * Process data for hashing with BLAKE256
 * 
 * The function can process multiples of 64 bytes,
 * any data in excess of a 64-byte multiple will be
 * ignored and must be processed when more data is
 * available or using `libblake_blake256_digest`
 * when the end of the input has been reached
 * 
 * @param   state  The state of the hash function
 * @param   data   The data to feed into the function
 * @param   len    The maximum number of bytes to process
 * @return         The number of processed bytes
 */
LIBBLAKE_PUBLIC__ size_t
libblake_blake256_update(struct libblake_blake256_state *state, const void *data, size_t len);

/**
 * Get the required allocation size of the
 * input buffer for `libblake_blake256_digest`
 * 
 * @param   len     The number of input whole bytes
 * @param   bits    The number of input bits after the last whole bytes
 *                  (may actually be greater than 7)
 * @param   suffix  String of '0's and '1's of addition bits to add to the
 *                  end of the input, or `NULL` (or the empty string) if none
 * @return          The number bytes required for the input buffer
 */
LIBBLAKE_PUBLIC__ LIBBLAKE_PURE__ inline size_t
libblake_blake256_digest_get_required_input_size(size_t len, size_t bits, const char *suffix) {
	return libblake_blake224_digest_get_required_input_size(len, bits, suffix);
}

/**
 * Calculate the input a BLAKE256 hash
 * 
 * The `state` parameter must be initialised using the
 * `libblake_blake256_init` function, after which, but
 * before this function is called, `libblake_blake256_update`
 * can be used to process data before this function is
 * called. Already processed data shall not be input to
 * this function.
 * 
 * @param  state   The state of the hash function
 * @param  data    Data to process; the function will write addition data to
 *                 the end, therefore the size of this buffer must be at least
 *                 `libblake_blake256_digest_get_required_input_size(len, bits, suffix)`
 *                 bytes large
 * @param  len     The number of input whole bytes
 * @param  bits    The number of input bits after the last whole bytes
 *                 (may actually be greater than 7); these bits shall
 *                 be stored in `data[len]`'s (addition bytes will be used
 *                 if `bits > 8`) lower bits
 * @param  suffix  String of '0's and '1's of addition bits to add to the
 *                 end of the input, or `NULL` (or the empty string) if none;
 *                 the first character corresponds to the lowest indexed
 *                 additional bit, and the last character corresponds to
 *                 the highest indexed additional bit
 * @param  output  Output buffer for the hash, which will be stored in raw
 *                 binary representation; the size of this buffer must be
 *                 at least `LIBBLAKE_BLAKE256_OUTPUT_SIZE` bytes
 */
LIBBLAKE_PUBLIC__ void
libblake_blake256_digest(struct libblake_blake256_state *state, void *data, size_t len, size_t bits,
                         const char *suffix, unsigned char output[static LIBBLAKE_BLAKE256_OUTPUT_SIZE]);



/**
 * Initialise a state for hashing with BLAKE384
 * 
 * @param  state  The state to initialise
 * @param  salt   16-byte salt to use, or `NULL` for an all-zeroes salt
 */
LIBBLAKE_PUBLIC__ void
libblake_blake384_init2(struct libblake_blake384_state *state, const uint_least8_t salt[32]);

/**
 * Initialise a state for hashing with BLAKE384
 * and an all-zeroes salt
 * 
 * @param  state  The state to initialise
 */
LIBBLAKE_PUBLIC__ inline void
libblake_blake384_init(struct libblake_blake384_state *state) {
	libblake_blake384_init2(state, NULL);
}

/**
 * Process data for hashing with BLAKE384
 * 
 * The function can process multiples of 128 bytes,
 * any data in excess of a 128-byte multiple will
 * be ignored and must be processed when more data
 * is available or using `libblake_blake384_digest`
 * when the end of the input has been reached
 * 
 * @param   state  The state of the hash function
 * @param   data   The data to feed into the function
 * @param   len    The maximum number of bytes to process
 * @return         The number of processed bytes
 */
LIBBLAKE_PUBLIC__ size_t
libblake_blake384_update(struct libblake_blake384_state *state, const void *data, size_t len);

/**
 * Get the required allocation size of the
 * input buffer for `libblake_blake384_digest`
 * 
 * @param   len     The number of input whole bytes
 * @param   bits    The number of input bits after the last whole bytes
 *                  (may actually be greater than 7)
 * @param   suffix  String of '0's and '1's of addition bits to add to the
 *                  end of the input, or `NULL` (or the empty string) if none
 * @return          The number bytes required for the input buffer
 */
LIBBLAKE_PUBLIC__ LIBBLAKE_PURE__ size_t
libblake_blake384_digest_get_required_input_size(size_t len, size_t bits, const char *suffix);

/**
 * Calculate the input a BLAKE384 hash
 * 
 * The `state` parameter must be initialised using the
 * `libblake_blake384_init` function, after which, but
 * before this function is called, `libblake_blake384_update`
 * can be used to process data before this function is
 * called. Already processed data shall not be input to
 * this function.
 * 
 * @param  state   The state of the hash function
 * @param  data    Data to process; the function will write addition data to
 *                 the end, therefore the size of this buffer must be at least
 *                 `libblake_blake384_digest_get_required_input_size(len, bits, suffix)`
 *                 bytes large
 * @param  len     The number of input whole bytes
 * @param  bits    The number of input bits after the last whole bytes
 *                 (may actually be greater than 7); these bits shall
 *                 be stored in `data[len]`'s (addition bytes will be used
 *                 if `bits > 8`) lower bits
 * @param  suffix  String of '0's and '1's of addition bits to add to the
 *                 end of the input, or `NULL` (or the empty string) if none;
 *                 the first character corresponds to the lowest indexed
 *                 additional bit, and the last character corresponds to
 *                 the highest indexed additional bit
 * @param  output  Output buffer for the hash, which will be stored in raw
 *                 binary representation; the size of this buffer must be
 *                 at least `LIBBLAKE_BLAKE384_OUTPUT_SIZE` bytes
 */
LIBBLAKE_PUBLIC__ void
libblake_blake384_digest(struct libblake_blake384_state *state, void *data, size_t len, size_t bits,
                         const char *suffix, unsigned char output[static LIBBLAKE_BLAKE384_OUTPUT_SIZE]);



/**
 * Initialise a state for hashing with BLAKE512
 * 
 * @param  state  The state to initialise
 * @param  salt   16-byte salt to use, or `NULL` for an all-zeroes salt
 */
LIBBLAKE_PUBLIC__ void
libblake_blake512_init2(struct libblake_blake512_state *state, const uint_least8_t salt[32]);

/**
 * Initialise a state for hashing with BLAKE512
 * and an all-zeroes salt
 * 
 * @param  state  The state to initialise
 */
LIBBLAKE_PUBLIC__ inline void
libblake_blake512_init(struct libblake_blake512_state *state) {
	libblake_blake512_init2(state, NULL);
}

/**
 * Process data for hashing with BLAKE512
 * 
 * The function can process multiples of 128 bytes,
 * any data in excess of a 128-byte multiple will
 * be ignored and must be processed when more data
 * is available or using `libblake_blake512_digest`
 * when the end of the input has been reached
 * 
 * @param   state  The state of the hash function
 * @param   data   The data to feed into the function
 * @param   len    The maximum number of bytes to process
 * @return         The number of processed bytes
 */
LIBBLAKE_PUBLIC__ size_t
libblake_blake512_update(struct libblake_blake512_state *state, const void *data, size_t len);

/**
 * Get the required allocation size of the
 * input buffer for `libblake_blake512_digest`
 * 
 * @param   len     The number of input whole bytes
 * @param   bits    The number of input bits after the last whole bytes
 *                  (may actually be greater than 7)
 * @param   suffix  String of '0's and '1's of addition bits to add to the
 *                  end of the input, or `NULL` (or the empty string) if none
 * @return          The number bytes required for the input buffer
 */
LIBBLAKE_PUBLIC__ LIBBLAKE_PURE__ inline size_t
libblake_blake512_digest_get_required_input_size(size_t len, size_t bits, const char *suffix) {
	return libblake_blake384_digest_get_required_input_size(len, bits, suffix);
}

/**
 * Calculate the input a BLAKE512 hash
 * 
 * The `state` parameter must be initialised using the
 * `libblake_blake512_init` function, after which, but
 * before this function is called, `libblake_blake512_update`
 * can be used to process data before this function is
 * called. Already processed data shall not be input to
 * this function.
 * 
 * @param  state   The state of the hash function
 * @param  data    Data to process; the function will write addition data to
 *                 the end, therefore the size of this buffer must be at least
 *                 `libblake_blake512_digest_get_required_input_size(len, bits, suffix)`
 *                 bytes large
 * @param  len     The number of input whole bytes
 * @param  bits    The number of input bits after the last whole bytes
 *                 (may actually be greater than 7); these bits shall
 *                 be stored in `data[len]`'s (addition bytes will be used
 *                 if `bits > 8`) lower bits
 * @param  suffix  String of '0's and '1's of addition bits to add to the
 *                 end of the input, or `NULL` (or the empty string) if none;
 *                 the first character corresponds to the lowest indexed
 *                 additional bit, and the last character corresponds to
 *                 the highest indexed additional bit
 * @param  output  Output buffer for the hash, which will be stored in raw
 *                 binary representation; the size of this buffer must be
 *                 at least `LIBBLAKE_BLAKE512_OUTPUT_SIZE` bytes
 */
LIBBLAKE_PUBLIC__ void
libblake_blake512_digest(struct libblake_blake512_state *state, void *data, size_t len, size_t bits,
                         const char *suffix, unsigned char output[static LIBBLAKE_BLAKE512_OUTPUT_SIZE]);



/*********************************** BLAKE2 ***********************************/

/**
 * BLAKE2s hashing parameters
 */
struct libblake_blake2s_params {
	uint_least8_t digest_len; /* in bytes, [1, 32] */
	uint_least8_t key_len; /* in bytes, [0, 32] */
	uint_least8_t fanout; /* normally 1 */
	uint_least8_t depth; /* normally 1 */
	uint_least32_t leaf_len; /* normally 0 */
	uint_least64_t node_offset; /* (48-bits) normally 0 */
	uint_least8_t node_depth; /* normally 0 */
	uint_least8_t inner_len; /* normally 0 */
	uint_least8_t _padding[2]; /* to keep .salt and .pepper aligned as uint_least32_t */
	uint_least8_t salt[8];
	uint_least8_t pepper[8];
};

/**
 * BLAKE2b hashing parameters
 */
struct libblake_blake2b_params {
	uint_least8_t digest_len; /* in bytes, [1, 64] */
	uint_least8_t key_len; /* in bytes, [0, 64] */
	uint_least8_t fanout; /* normally 1 */
	uint_least8_t depth; /* normally 1 */
	uint_least32_t leaf_len; /* normally 0 */
	uint_least64_t node_offset; /* normally 0 */
	uint_least8_t node_depth; /* normally 0 */
	uint_least8_t inner_len; /* normally 0 */
	uint_least8_t _padding[6]; /* to keep .salt and .pepper aligned as uint_least64_t */
	uint_least8_t salt[16];
	uint_least8_t pepper[16];
};

/**
 * State for BLAKE2s hashing
 * 
 * This structure should be opaque
 */
struct libblake_blake2s_state {
	LIBBLAKE_ALIGNED__(32)
	uint_least32_t h[8];
	uint_least32_t t[2];
	uint_least32_t f[2];
};

/**
 * State for BLAKE2b hashing
 * 
 * This structure should be opaque
 */
struct libblake_blake2b_state {
	LIBBLAKE_ALIGNED__(32)
	uint_least64_t h[8];
	uint_least64_t t[2];
	uint_least64_t f[2];
};



LIBBLAKE_PUBLIC__ void
libblake_blake2s_init(struct libblake_blake2s_state *state, const struct libblake_blake2s_params *params,
                      const unsigned char *key /* append null bytes until 64 bytes; if key is used */);

LIBBLAKE_PUBLIC__ size_t
libblake_blake2s_update(struct libblake_blake2s_state *state, const void *data, size_t len);

LIBBLAKE_PUBLIC__ size_t
libblake_blake2s_force_update(struct libblake_blake2s_state *state, const void *data, size_t len);

LIBBLAKE_PUBLIC__ LIBBLAKE_CONST__ size_t
libblake_blake2s_digest_get_required_input_size(size_t len);

LIBBLAKE_PUBLIC__ void
libblake_blake2s_digest(struct libblake_blake2s_state *state, void *data, size_t len, int last_node /* normally 0 */,
                        size_t output_len, unsigned char output[static output_len]);



LIBBLAKE_PUBLIC__ void
libblake_blake2b_init(struct libblake_blake2b_state *state, const struct libblake_blake2b_params *params,
                      const unsigned char *key /* append null bytes until 128 bytes; if key is used */);

LIBBLAKE_PUBLIC__ size_t
libblake_blake2b_update(struct libblake_blake2b_state *state, const void *data, size_t len);

LIBBLAKE_PUBLIC__ size_t
libblake_blake2b_force_update(struct libblake_blake2b_state *state, const void *data, size_t len);

LIBBLAKE_PUBLIC__ LIBBLAKE_CONST__ size_t
libblake_blake2b_digest_get_required_input_size(size_t len);

LIBBLAKE_PUBLIC__ void
libblake_blake2b_digest(struct libblake_blake2b_state *state, void *data, size_t len, int last_node /* normally 0 */,
                        size_t output_len, unsigned char output[static output_len]);



/*********************************** BLAKE2X ***********************************/

/**
 * BLAKE2Xs hashing parameters
 */
struct libblake_blake2xs_params {
	uint_least8_t digest_len; /* in bytes, [1, 32] */
	uint_least8_t key_len; /* in bytes, [0, 32] */
	uint_least8_t fanout; /* normally 1 */
	uint_least8_t depth; /* normally 1 */
	uint_least32_t leaf_len; /* normally 0 */
	uint_least32_t node_offset; /* normally 0 */
	uint_least16_t xof_len; /* max if not known in advance */
	uint_least8_t node_depth; /* normally 0 */
	uint_least8_t inner_len; /* normally 0 */
	uint_least8_t salt[8];
	uint_least8_t pepper[8];
};

/**
 * BLAKE2Xb hashing parameters
 */
struct libblake_blake2xb_params {
	uint_least8_t digest_len; /* in bytes, [1, 64] */
	uint_least8_t key_len; /* in bytes, [0, 64] */
	uint_least8_t fanout; /* normally 1 */
	uint_least8_t depth; /* normally 1 */
	uint_least32_t leaf_len; /* normally 0 */
	uint_least32_t node_offset; /* normally 0 */
	uint_least32_t xof_len; /* max if not known in advance */
	uint_least8_t node_depth; /* normally 0 */
	uint_least8_t inner_len; /* normally 0 */
	uint_least8_t _padding[2]; /* to keep .salt and .pepper aligned as uint_least32_t */
	uint_least8_t salt[16];
	uint_least8_t pepper[16];
};

/**
 * State for BLAKE2Xs hashing
 * 
 * This structure should be opaque
 */
struct libblake_blake2xs_state {
	struct libblake_blake2s_state b2s;
	struct libblake_blake2xs_params xof_params;
	unsigned char intermediate[64];
};

/**
 * State for BLAKE2Xb hashing
 * 
 * This structure should be opaque
 */
struct libblake_blake2xb_state {
	struct libblake_blake2b_state b2b;
	struct libblake_blake2xb_params xof_params;
	unsigned char intermediate[128];
};



LIBBLAKE_PUBLIC__ void
libblake_blake2xs_init(struct libblake_blake2xs_state *state, const struct libblake_blake2xs_params *params,
                       const unsigned char *key /* append null bytes until 64 bytes; if key is used */);

LIBBLAKE_PUBLIC__ inline size_t
libblake_blake2xs_update(struct libblake_blake2xs_state *state, const void *data, size_t len) {
	return libblake_blake2s_update(&state->b2s, data, len);
}

LIBBLAKE_PUBLIC__ inline size_t
libblake_blake2xs_force_update(struct libblake_blake2xs_state *state, const void *data, size_t len) {
	return libblake_blake2s_force_update(&state->b2s, data, len);
}

LIBBLAKE_PUBLIC__ inline void
libblake_blake2xs_predigest(struct libblake_blake2xs_state *state, void *data, size_t len, int last_node) {
	libblake_blake2s_digest(&state->b2s, data, len, last_node, (size_t)state->xof_params.digest_len, state->intermediate);
}

LIBBLAKE_PUBLIC__ LIBBLAKE_PURE__ inline size_t
libblake_blake2xs_predigest_get_required_input_size(const struct libblake_blake2xs_state *state) {
	return libblake_blake2s_digest_get_required_input_size((size_t)state->xof_params.digest_len);
}

LIBBLAKE_PUBLIC__ void
libblake_blake2xs_digest(const struct libblake_blake2xs_state *state,
                         uint_least32_t i /* start 0, increase by 1 until i * 32 >= desired hash length */,
                         uint_least8_t len /* desired hash MIN(length - i * 32, 32) */,
                         unsigned char output[static len] /* output for hash offset by i * 32 */);



LIBBLAKE_PUBLIC__ void
libblake_blake2xb_init(struct libblake_blake2xb_state *state, const struct libblake_blake2xb_params *params,
                       const unsigned char *key /* append null bytes until 128 bytes; if key is used */);

LIBBLAKE_PUBLIC__ inline size_t
libblake_blake2xb_update(struct libblake_blake2xb_state *state, const void *data, size_t len) {
	return libblake_blake2b_update(&state->b2b, data, len);
}

LIBBLAKE_PUBLIC__ inline size_t
libblake_blake2xb_force_update(struct libblake_blake2xb_state *state, const void *data, size_t len) {
	return libblake_blake2b_update(&state->b2b, data, len);
}

LIBBLAKE_PUBLIC__ inline void
libblake_blake2xb_predigest(struct libblake_blake2xb_state *state, void *data, size_t len, int last_node) {
	libblake_blake2b_digest(&state->b2b, data, len, last_node, state->xof_params.digest_len, state->intermediate);
}

LIBBLAKE_PUBLIC__ LIBBLAKE_PURE__ inline size_t
libblake_blake2xb_predigest_get_required_input_size(const struct libblake_blake2xb_state *state) {
	return libblake_blake2b_digest_get_required_input_size((size_t)state->xof_params.digest_len);
}

LIBBLAKE_PUBLIC__ void
libblake_blake2xb_digest(const struct libblake_blake2xb_state *state,
                         uint_least32_t i /* start 0, increase by 1 until i * 64 >= desired hash length */,
                         uint_least8_t len /* desired hash MIN(length - i * 64, 64) */,
                         unsigned char output[static len] /* output for hash offset by i * 64 */);



#if defined(__clang__)
# pragma clang diagnostic pop
#endif

#endif
