/* See LICENSE file for copyright and license details. */
#include "common.h"

size_t
libblake_blake2s_update(struct libblake_blake2s_state *state, const void *data_, size_t len)
{
	const unsigned char *data = data_;
	size_t off = 0;

	for (; len - off > 64; off += 64) {
		/* See libblake_blake2s_force_update.c for optimisations notes */
		state->t[0] = (state->t[0] + 64) & UINT_LEAST32_C(0xFFFFffff);
		if (state->t[0] < 64)
			state->t[1] = (state->t[1] + 1) & UINT_LEAST32_C(0xFFFFffff);

		libblake_internal_blake2s_compress(state, &data[off]);
	}

	return off;
}
