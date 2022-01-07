/* See LICENSE file for copyright and license details. */
#include "common.h"

static void
encode_uint64_le(unsigned char *out, uint_least64_t value, size_t bytes)
{
	switch (bytes) {
	default:
		out[7] = (unsigned char)((value >> 56) & 255);
		/* fall through */
	case 7:
		out[6] = (unsigned char)((value >> 48) & 255);
		/* fall through */
	case 6:
		out[5] = (unsigned char)((value >> 40) & 255);
		/* fall through */
	case 5:
		out[4] = (unsigned char)((value >> 32) & 255);
		/* fall through */
	case 4:
		out[3] = (unsigned char)((value >> 24) & 255);
		/* fall through */
	case 3:
		out[2] = (unsigned char)((value >> 16) & 255);
		/* fall through */
	case 2:
		out[1] = (unsigned char)((value >>  8) & 255);
		/* fall through */
	case 1:
		out[0] = (unsigned char)((value >>  0) & 255);
		/* fall through */
	case 0:
		break;
	}
}

void
libblake_blake2b_digest(struct libblake_blake2b_state *state, void *data_, size_t len,
                        size_t output_len, unsigned char output[static output_len])
{
	unsigned char *data = data_;
	size_t r, i, j;

	r = libblake_blake2b_update(state, data, len);
	data = &data[r];
	len -= r;

	state->f[0] = UINT_LEAST64_C(0xFFFFffffFFFFffff);
	memset(&data[len], 0, 128 - len);

	state->t[0] = (state->t[0] + len) & UINT_LEAST64_C(0xFFFFffffFFFFffff);
	if (state->t[0] < len)
		state->t[1] = (state->t[1] + 1) & UINT_LEAST64_C(0xFFFFffffFFFFffff);

	libblake_internal_blake2b_compress(state, data);

	for (i = 0, j = 0; i < output_len; i += 8, j += 1)
		encode_uint64_le(&output[i], state->h[j], output_len - i);
}
