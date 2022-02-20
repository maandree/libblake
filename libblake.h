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
 * The function can only process multiples of 64 bytes,
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
 * Calculate the BLAKE224 hash of the input data
 * 
 * The `state` parameter must have been initialised using
 * the `libblake_blake224_init` function, after which, but
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
 * The function can only process multiples of 64 bytes,
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
 * Calculate the BLAKE256 hash of the input data
 * 
 * The `state` parameter must have been initialised using
 * the `libblake_blake256_init` function, after which, but
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
 * @param  salt   32-byte salt to use, or `NULL` for an all-zeroes salt
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
 * The function can only process multiples of 128 bytes,
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
 * Calculate the BLAKE384 hash of the input data
 * 
 * The `state` parameter must have been initialised using
 * the `libblake_blake384_init` function, after which, but
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
 * @param  salt   32-byte salt to use, or `NULL` for an all-zeroes salt
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
 * The function can only process multiples of 128 bytes,
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
 * Calculate the BLAKE512 hash of the input data
 * 
 * The `state` parameter must have been initialised using
 * the `libblake_blake512_init` function, after which, but
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

	/**
	 * The size of the output hash, in bytes
	 * (in its raw binary encoding, i.e. before
	 * encoded to hexadecimal or other text
	 * encoding)
	 * 
	 * This value shall be between within [1, 32]
	 */
	uint_least8_t digest_len;

	/**
	 * The size of the key, in bytes
	 * 
	 * This value shall be 0 for unkeyed mode
	 * and within [1, 32] for keyed mode
	 * 
	 * Keyed mode is used for MAC and PRF
	 */
	uint_least8_t key_len;

	/**
	 * The fan-out on each non-root node
	 * in tree hashing, 0 for unlimited
	 * 
	 * Set to 1 if not using tree-hashing
	 */
	uint_least8_t fanout;

	/**
	 * The maximum depth of the hashing tree,
	 * 255 for unlimited, 0 is forbidden
	 * 
	 * It is recommended that 2 is used
	 * (the value will affect the resulting
	 * hashing) if the fan-out is unlimited
	 * 
	 * Set to 1 if not using tree-hashing
	 */
	uint_least8_t depth;

	/**
	 * The number of bytes from the input to
	 * process at each leaf in the hashing
	 * tree; 0 if unlimited
	 * 
	 * Set to 0 if not using tree-hashing
	 */
	uint_least32_t leaf_len;

	/**
	 * The offset of the current node in the
	 * hashing tree
	 * 
	 * For leaf nodes, this is the position
	 * in the input, that is being processed
	 * by the current node in the hashing
	 * tree, divided by `.leaf_len`, or 0 if
	 * `.leaf_len` is 0. For non-leaf nodes
	 * this value is further divided by the
	 * fan-out once per level removed from
	 * the leaf nodes.
	 * 
	 * This value is limited to 48 bits.
	 * 
	 * Set to 0 if not using tree-hashing
	 */
	uint_least64_t node_offset;

	/**
	 * The depth of the current node in the
	 * hashing tree
	 * 
	 * This value is 0 for the root node,
	 * and plus 1 per level down the tree
	 * 
	 * Set to 0 if not using tree-hashing
	 */
	uint_least8_t node_depth;

	/**
	 * Inner hash (the intermediate hash
	 * produced at each node except the
	 * root node) length, in bytes
	 * 
	 * This value shall be between within
	 * [1, 32] for tree-hashing
	 * 
	 * Set to 0 if not using tree-hashing
	 */
	uint_least8_t inner_len;

	uint_least8_t _padding[2]; /* to keep .salt and .pepper aligned as uint_least32_t */

	/**
	 * 8-byte salt used to make the hash
	 * unique even if the input is not unique
	 * 
	 * These is normally used in password hashing
	 * schemes to avoid duplicate hashing where
	 * two user's have the same password, and,
	 * more importantly, to prevent rainbow-table
	 * attacks
	 * 
	 * This is normally not used when producing
	 * checksum for files, and should normally
	 * be all NUL bytes in such cases
	 */
	uint_least8_t salt[8];

	/**
	 * 8-byte pepper ("personalisation") used to
	 * make the hash application-unique
	 * 
	 * These is normally used (in the rare cases
	 * when it is used) in password hashing
	 * schemes as an extra level of security
	 * (through obscurity; something that is OK
	 * only when it is an _extra_ level of
	 * security). A pepper must not be stored
	 * in a password database; it should be
	 * compiled into the application that
	 * calculates the hash, to avoid it being
	 * accessed by a hacker when he gets access
	 * to the password table.
	 * 
	 * This is normally not used when producing
	 * checksum for files, and should normally
	 * be all NUL bytes in such cases
	 */
	uint_least8_t pepper[8];
};

/**
 * BLAKE2b hashing parameters
 */
struct libblake_blake2b_params {

	/**
	 * The size of the output hash, in bytes
	 * (in its raw binary encoding, i.e. before
	 * encoded to hexadecimal or other text
	 * encoding)
	 * 
	 * This value shall be between within [1, 64]
	 */
	uint_least8_t digest_len;

	/**
	 * The size of the key, in bytes
	 * 
	 * This value shall be 0 for unkeyed mode
	 * and within [1, 64] for keyed mode
	 * 
	 * Keyed mode is used for MAC and PRF
	 */
	uint_least8_t key_len;

	/**
	 * The fan-out on each non-root node
	 * in tree hashing
	 * 
	 * Set to 1 if not using tree-hashing
	 */
	uint_least8_t fanout;

	/**
	 * The maximum depth of the hashing tree,
	 * 255 for unlimited, 0 is forbidden
	 * 
	 * It is recommended that 2 is used
	 * (the value will affect the resulting
	 * hashing) if the fan-out is unlimited
	 * 
	 * Set to 1 if not using tree-hashing
	 */
	uint_least8_t depth;

	/**
	 * The number of bytes from the input to
	 * process at each leaf in the hashing
	 * tree; 0 if unlimited
	 * 
	 * Set to 0 if not using tree-hashing
	 */
	uint_least32_t leaf_len;

	/**
	 * The offset of the current node in the
	 * hashing tree
	 * 
	 * For leaf nodes, this is the position
	 * in the input, that is being processed
	 * by the current node in the hashing
	 * tree, divided by `.leaf_len`, or 0 if
	 * `.leaf_len` is 0. For non-leaf nodes
	 * this value is further divided by the
	 * fan-out once per level removed from
	 * the leaf nodes.
	 * 
	 * Set to 0 if not using tree-hashing
	 */
	uint_least64_t node_offset;

	/**
	 * The depth of the current node in the
	 * hashing tree
	 * 
	 * This value is 0 for the root node,
	 * and plus 1 per level down the tree
	 * 
	 * Set to 0 if not using tree-hashing
	 */
	uint_least8_t node_depth;

	/**
	 * Inner hash (the intermediate hash
	 * produced at each node except the
	 * root node) length, in bytes
	 * 
	 * This value shall be between within
	 * [1, 32] for tree-hashing
	 * 
	 * Set to 0 if not using tree-hashing
	 */
	uint_least8_t inner_len;

	uint_least8_t _padding[6]; /* to keep .salt and .pepper aligned as uint_least64_t */

	/**
	 * 8-byte salt used to make the hash
	 * unique even if the input is not unique
	 * 
	 * These is normally used in password hashing
	 * schemes to avoid duplicate hashing where
	 * two user's have the same password, and,
	 * more importantly, to prevent rainbow-table
	 * attacks
	 * 
	 * This is normally not used when producing
	 * checksum for files, and should normally
	 * be all NUL bytes in such cases
	 */
	uint_least8_t salt[16];

	/**
	 * 16-byte pepper ("personalisation") used to
	 * make the hash application-unique
	 * 
	 * These is normally used (in the rare cases
	 * when it is used) in password hashing
	 * schemes as an extra level of security
	 * (through obscurity; something that is OK
	 * only when it is an _extra_ level of
	 * security). A pepper must not be stored
	 * in a password database; it should be
	 * compiled into the application that
	 * calculates the hash, to avoid it being
	 * accessed by a hacker when he gets access
	 * to the password table.
	 * 
	 * This is normally not used when producing
	 * checksum for files, and should normally
	 * be all NUL bytes in such cases
	 */
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



/**
 * Initialise a state for hashing with BLAKE2s
 * 
 * For keyed mode, which is used for MAC and PRF,
 * after calling this function, the 64 first bytes
 * input to the hash function shall be the key
 * with NUL bytes appended to it (such that the
 * length is 64 bytes, which is double the maximum
 * allowed length of the key, but is the size
 * block size used by BLAKE2s)
 * 
 * @param  state   The state to initialise
 * @param  params  Hashing parameters
 */
LIBBLAKE_PUBLIC__ void
libblake_blake2s_init(struct libblake_blake2s_state *state, const struct libblake_blake2s_params *params);

/**
 * Process data for hashing with BLAKE2s
 * 
 * The function can only process multiples of 64 bytes,
 * but cannot process that last chunk of 64 bytes
 * unless a non-multiple of 64 bytes is input to the
 * function; any excess data will be ignored and must
 * be processed when more data is available or using
 * `libblake_blake2s_digest` when the end of the
 * input has been reached
 * 
 * @param   state  The state of the hash function
 * @param   data   The data to feed into the function
 * @param   len    The maximum number of bytes to process
 * @return         The number of processed bytes
 */
LIBBLAKE_PUBLIC__ size_t
libblake_blake2s_update(struct libblake_blake2s_state *state, const void *data, size_t len);

/**
 * Process data for hashing with BLAKE2s
 * 
 * The function can only process multiples of 64 bytes,
 * any excess data will be ignored and must be
 * processed when more data is available or using
 * `libblake_blake2s_digest` when the end of the input
 * has been reached
 * 
 * Unlike `libblake_blake2s_update`, this function
 * will all input data if `len` is a multiple of
 * 64, however the application must make sure that
 * there is more data to process
 * 
 * @param   state  The state of the hash function
 * @param   data   The data to feed into the function
 * @param   len    The maximum number of bytes to process
 * @return         The number of processed bytes
 */
LIBBLAKE_PUBLIC__ size_t
libblake_blake2s_force_update(struct libblake_blake2s_state *state, const void *data, size_t len);

/**
 * Get the required allocation size of the
 * input buffer for `libblake_blake2s_digest`
 * 
 * @param   len  The number of input bytes
 * @return       The number bytes required for the input buffer
 */
LIBBLAKE_PUBLIC__ LIBBLAKE_CONST__ size_t
libblake_blake2s_digest_get_required_input_size(size_t len);

/**
 * Calculate the BLAKE2s hash of the input data
 * 
 * The `state` parameter must have been initialised using
 * the `libblake_blake2s_init` function, after which, but
 * before this function is called, `libblake_blake2s_update`
 * and `libblake_blake2s_force_update` can be used to
 * process data before this function is called. Already
 * processed data shall not be input to this function.
 * 
 * @param  state       The state of the hash function
 * @param  data        Data to process; the function will write addition data to
 *                     the end, therefore the size of this buffer must be at least
 *                     `libblake_blake2s_digest_get_required_input_size(len)`
 *                     bytes large
 * @param  len         The number of input bytes
 * @param  last_node   Shall be non-0 the last node at each level in the
 *                     hashing tree, include the root node, however, it
 *                     shall be 0 if not using tree-hashing
 * @param  output_len  The number of bytes to write to `output_len`; this
 *                     shall be the value `params->digest_len` had when
 *                     `libblake_blake2s_init` was called, where `params`
 *                     is the second argument given to `libblake_blake2s_init`
 * @param  output      Output buffer for the hash, which will be stored in raw
 *                     binary representation; the size of this buffer must be
 *                     at least `output_len` bytes
 */
LIBBLAKE_PUBLIC__ void
libblake_blake2s_digest(struct libblake_blake2s_state *state, void *data, size_t len, int last_node,
                        size_t output_len, unsigned char output[static output_len]);



/**
 * Initialise a state for hashing with BLAKE2b
 * 
 * For keyed mode, which is used for MAC and PRF,
 * after calling this function, the 128 first bytes
 * input to the hash function shall be the key
 * with NUL bytes appended to it (such that the
 * length is 128 bytes, which is double the maximum
 * allowed length of the key, but is the size
 * block size used by BLAKE2b)
 * 
 * @param  state   The state to initialise
 * @param  params  Hashing parameters
 */
LIBBLAKE_PUBLIC__ void
libblake_blake2b_init(struct libblake_blake2b_state *state, const struct libblake_blake2b_params *params);

/**
 * Process data for hashing with BLAKE2b
 * 
 * The function can only process multiples of 128 bytes,
 * but cannot process that last chunk of 128 bytes
 * unless a non-multiple of 128 bytes is input to the
 * function; any excess data will be ignored and must
 * be processed when more data is available or using
 * `libblake_blake2b_digest` when the end of the
 * input has been reached
 * 
 * @param   state  The state of the hash function
 * @param   data   The data to feed into the function
 * @param   len    The maximum number of bytes to process
 * @return         The number of processed bytes
 */
LIBBLAKE_PUBLIC__ size_t
libblake_blake2b_update(struct libblake_blake2b_state *state, const void *data, size_t len);

/**
 * Process data for hashing with BLAKE2b
 * 
 * The function can only process multiples of 128 bytes,
 * any excess data will be ignored and must be
 * processed when more data is available or using
 * `libblake_blake2s_digest` when the end of the input
 * has been reached
 * 
 * Unlike `libblake_blake2b_update`, this function
 * will all input data if `len` is a multiple of
 * 128, however the application must make sure that
 * there is more data to process
 * 
 * @param   state  The state of the hash function
 * @param   data   The data to feed into the function
 * @param   len    The maximum number of bytes to process
 * @return         The number of processed bytes
 */
LIBBLAKE_PUBLIC__ size_t
libblake_blake2b_force_update(struct libblake_blake2b_state *state, const void *data, size_t len);

/**
 * Get the required allocation size of the
 * input buffer for `libblake_blake2b_digest`
 * 
 * @param   len  The number of input bytes
 * @return       The number bytes required for the input buffer
 */
LIBBLAKE_PUBLIC__ LIBBLAKE_CONST__ size_t
libblake_blake2b_digest_get_required_input_size(size_t len);

/**
 * Calculate the BLAKE2b hash of the input data
 * 
 * The `state` parameter must have been initialised using
 * the `libblake_blake2b_init` function, after which, but
 * before this function is called, `libblake_blake2b_update`
 * and `libblake_blake2b_force_update` can be used to
 * process data before this function is called. Already
 * processed data shall not be input to this function.
 * 
 * @param  state       The state of the hash function
 * @param  data        Data to process; the function will write addition data to
 *                     the end, therefore the size of this buffer must be at least
 *                     `libblake_blake2b_digest_get_required_input_size(len)`
 *                     bytes large
 * @param  len         The number of input bytes
 * @param  last_node   Shall be non-0 the last node at each level in the
 *                     hashing tree, include the root node, however, it
 *                     shall be 0 if not using tree-hashing
 * @param  output_len  The number of bytes to write to `output_len`; this
 *                     shall be the value `params->digest_len` had when
 *                     `libblake_blake2b_init` was called, where `params`
 *                     is the second argument given to `libblake_blake2b_init`
 * @param  output      Output buffer for the hash, which will be stored in raw
 *                     binary representation; the size of this buffer must be
 *                     at least `output_len` bytes
 */
LIBBLAKE_PUBLIC__ void
libblake_blake2b_digest(struct libblake_blake2b_state *state, void *data, size_t len, int last_node,
                        size_t output_len, unsigned char output[static output_len]);



/*********************************** BLAKE2X (!!DRAFT!!) ***********************************/

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



/**
 * Initialise a state for hashing with BLAKE2Xs
 * 
 * NB! BLAKE2X has not been finalised as of 2022-02-20
 * 
 * @param  state   The state to initialise
 * @param  params  Hashing parameters
 */
LIBBLAKE_PUBLIC__ void
libblake_blake2xs_init(struct libblake_blake2xs_state *state, const struct libblake_blake2xs_params *params);

/**
 * Process data for hashing with BLAKE2Xs
 * 
 * The function can only process multiples of 64 bytes,
 * but cannot process that last chunk of 64 bytes
 * unless a non-multiple of 64 bytes is input to the
 * function; any excess data will be ignored and must
 * be processed when more data is available or using
 * `libblake_blake2xs_predigest` when the end of the
 * input has been reached
 * 
 * @param   state  The state of the hash function
 * @param   data   The data to feed into the function
 * @param   len    The maximum number of bytes to process
 * @return         The number of processed bytes
 */
LIBBLAKE_PUBLIC__ inline size_t
libblake_blake2xs_update(struct libblake_blake2xs_state *state, const void *data, size_t len) {
	return libblake_blake2s_update(&state->b2s, data, len);
}

/**
 * Process data for hashing with BLAKE2Xs
 * 
 * The function can only process multiples of 64 bytes,
 * any excess data will be ignored and must be
 * processed when more data is available or using
 * `libblake_blake2xs_predigest` when the end of the
 * input has been reached
 * 
 * Unlike `libblake_blake2xs_update`, this function
 * will all input data if `len` is a multiple of
 * 64, however the application must make sure that
 * there is more data to process
 * 
 * @param   state  The state of the hash function
 * @param   data   The data to feed into the function
 * @param   len    The maximum number of bytes to process
 * @return         The number of processed bytes
 */
LIBBLAKE_PUBLIC__ inline size_t
libblake_blake2xs_force_update(struct libblake_blake2xs_state *state, const void *data, size_t len) {
	return libblake_blake2s_force_update(&state->b2s, data, len);
}

/**
 * Get the required allocation size of the
 * input buffer for `libblake_blake2xs_predigest`
 * 
 * @param   len  The number of input bytes
 * @return       The number bytes required for the input buffer
 */
LIBBLAKE_PUBLIC__ LIBBLAKE_PURE__ inline size_t
libblake_blake2xs_predigest_get_required_input_size(const struct libblake_blake2xs_state *state) {
	return libblake_blake2s_digest_get_required_input_size((size_t)state->xof_params.digest_len);
}

/**
 * Perform intermediate hashing calculation for
 * a BLAKE2Xs hash at the end of the input data
 * 
 * The `state` parameter must have been initialised using
 * the `libblake_blake2xs_init` function, after which, but
 * before this function is called, `libblake_blake2xs_update`
 * and `libblake_blake2xs_force_update` can be used to
 * process data before this function is called. Already
 * processed data shall not be input to this function.
 * 
 * @param  state       The state of the hash function
 * @param  data        Data to process; the function will write addition data to
 *                     the end, therefore the size of this buffer must be at least
 *                     `libblake_blake2xs_digest_get_required_input_size(len)`
 *                     bytes large
 * @param  len         The number of input bytes
 * @param  last_node   Shall be non-0 the last node at each level in the
 *                     hashing tree, include the root node, however, it
 *                     shall be 0 if not using tree-hashing
 */
LIBBLAKE_PUBLIC__ inline void
libblake_blake2xs_predigest(struct libblake_blake2xs_state *state, void *data, size_t len, int last_node) {
	libblake_blake2s_digest(&state->b2s, data, len, last_node, (size_t)state->xof_params.digest_len, state->intermediate);
}

/**
 * Calculate part of a BLAKE2Xs hashing
 * 
 * All parts of the hash can be calculated in parallel
 * 
 * The `state` parameter must have preprocessed
 * using the `libblake_blake2xs_predigest` function
 * 
 * @param  state   The state of the hash function
 * @param  i       The index of the portion of the hash that
 *                 shall be calculated, that is, the offset in
 *                 the hash divided by 32, meaning that it
 *                 shall be 0 when calculating the first 32
 *                 bytes, and hash calculation stops when
 *                 `i * 32` is equal to or greater than the
 *                 desired hash length
 * @param  len     Given the desired total hash length, in bytes,
 *                 `length`, `len` shall be the minimum of `32`
 *                 and `length - i * 32`
 * @param  output  Output buffer for the hash offset by `i * 32`
 */
LIBBLAKE_PUBLIC__ void
libblake_blake2xs_digest(const struct libblake_blake2xs_state *state, uint_least32_t i,
                         uint_least8_t len, unsigned char output[static len]);



/**
 * Initialise a state for hashing with BLAKE2Xb
 * 
 * NB! BLAKE2X has not been finalised as of 2022-02-20
 * 
 * @param  state   The state to initialise
 * @param  params  Hashing parameters
 */
LIBBLAKE_PUBLIC__ void
libblake_blake2xb_init(struct libblake_blake2xb_state *state, const struct libblake_blake2xb_params *params);

/**
 * Process data for hashing with BLAKE2Xb
 * 
 * The function can only process multiples of 128 bytes,
 * but cannot process that last chunk of 128 bytes
 * unless a non-multiple of 128 bytes is input to the
 * function; any excess data will be ignored and must
 * be processed when more data is available or using
 * `libblake_blake2xb_predigest` when the end of the
 * input has been reached
 * 
 * @param   state  The state of the hash function
 * @param   data   The data to feed into the function
 * @param   len    The maximum number of bytes to process
 * @return         The number of processed bytes
 */
LIBBLAKE_PUBLIC__ inline size_t
libblake_blake2xb_update(struct libblake_blake2xb_state *state, const void *data, size_t len) {
	return libblake_blake2b_update(&state->b2b, data, len);
}

/**
 * Process data for hashing with BLAKE2Xb
 * 
 * The function can only process multiples of 128 bytes,
 * any excess data will be ignored and must be
 * processed when more data is available or using
 * `libblake_blake2xs_predigest` when the end of the
 * input has been reached
 * 
 * Unlike `libblake_blake2xb_update`, this function
 * will all input data if `len` is a multiple of
 * 128, however the application must make sure that
 * there is more data to process
 * 
 * @param   state  The state of the hash function
 * @param   data   The data to feed into the function
 * @param   len    The maximum number of bytes to process
 * @return         The number of processed bytes
 */
LIBBLAKE_PUBLIC__ inline size_t
libblake_blake2xb_force_update(struct libblake_blake2xb_state *state, const void *data, size_t len) {
	return libblake_blake2b_update(&state->b2b, data, len);
}

/**
 * Get the required allocation size of the
 * input buffer for `libblake_blake2xb_predigest`
 * 
 * @param   len  The number of input bytes
 * @return       The number bytes required for the input buffer
 */
LIBBLAKE_PUBLIC__ LIBBLAKE_PURE__ inline size_t
libblake_blake2xb_predigest_get_required_input_size(const struct libblake_blake2xb_state *state) {
	return libblake_blake2b_digest_get_required_input_size((size_t)state->xof_params.digest_len);
}

/**
 * Perform intermediate hashing calculation for
 * a BLAKE2Xb hash at the end of the input data
 * 
 * The `state` parameter must have been initialised using
 * the `libblake_blake2xb_init` function, after which, but
 * before this function is called, `libblake_blake2xb_update`
 * and `libblake_blake2xb_force_update` can be used to
 * process data before this function is called. Already
 * processed data shall not be input to this function.
 * 
 * @param  state       The state of the hash function
 * @param  data        Data to process; the function will write addition data to
 *                     the end, therefore the size of this buffer must be at least
 *                     `libblake_blake2xb_digest_get_required_input_size(len)`
 *                     bytes large
 * @param  len         The number of input bytes
 * @param  last_node   Shall be non-0 the last node at each level in the
 *                     hashing tree, include the root node, however, it
 *                     shall be 0 if not using tree-hashing
 */
LIBBLAKE_PUBLIC__ inline void
libblake_blake2xb_predigest(struct libblake_blake2xb_state *state, void *data, size_t len, int last_node) {
	libblake_blake2b_digest(&state->b2b, data, len, last_node, state->xof_params.digest_len, state->intermediate);
}

/**
 * Calculate part of a BLAKE2Xb hashing
 * 
 * All parts of the hash can be calculated in parallel
 * 
 * The `state` parameter must have preprocessed
 * using the `libblake_blake2xb_predigest` function
 * 
 * @param  state   The state of the hash function
 * @param  i       The index of the portion of the hash that
 *                 shall be calculated, that is, the offset in
 *                 the hash divided by 64, meaning that it
 *                 shall be 0 when calculating the first 64
 *                 bytes, and hash calculation stops when
 *                 `i * 64` is equal to or greater than the
 *                 desired hash length
 * @param  len     Given the desired total hash length, in bytes,
 *                 `length`, `len` shall be the minimum of `64`
 *                 and `length - i * 64`
 * @param  output  Output buffer for the hash offset by `i * 64`
 */
LIBBLAKE_PUBLIC__ void
libblake_blake2xb_digest(const struct libblake_blake2xb_state *state, uint_least32_t i,
                         uint_least8_t len, unsigned char output[static len]);



#if defined(__clang__)
# pragma clang diagnostic pop
#endif

#endif
