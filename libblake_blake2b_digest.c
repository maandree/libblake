/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake2b_digest(struct libblake_blake2b_state *state, void *data_, size_t len, int last_node,
                        size_t output_len, unsigned char output[static output_len])
{
	unsigned char *data = data_;
	size_t r;

	r = libblake_blake2b_update(state, data, len);
	data = &data[r];
	len -= r;

	state->f[0] = UINT_LEAST64_C(0xFFFFffffFFFFffff);
	if (last_node)
		state->f[1] = UINT_LEAST64_C(0xFFFFffffFFFFffff);

	memset(&data[len], 0, 128 - len);

	state->t[0] = (state->t[0] + len) & UINT_LEAST64_C(0xFFFFffffFFFFffff);
	if (state->t[0] < len)
		state->t[1] = (state->t[1] + 1) & UINT_LEAST64_C(0xFFFFffffFFFFffff);

	libblake_internal_blake2b_compress(state, data);

	libblake_internal_blake2b_output_digest(state, output_len, output);
}
