/* See LICENSE file for copyright and license details. */
#include "common.h"

size_t
libblake_blake2b_force_update(struct libblake_blake2b_state *state, const void *data_, size_t len)
{
	const unsigned char *data = data_;
	size_t off = 0;

	for (; len - off >= 128; off += 128) {
		state->t[0] = (state->t[0] + 128) & UINT_LEAST64_C(0xFFFFffffFFFFffff);
		if (state->t[0] < 128)
			state->t[1] = (state->t[1] + 1) & UINT_LEAST64_C(0xFFFFffffFFFFffff);

		libblake_internal_blake2b_compress(state, &data[off]);
	}

	return off;
}
