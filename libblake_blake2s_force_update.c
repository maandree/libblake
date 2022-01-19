/* See LICENSE file for copyright and license details. */
#include "common.h"

size_t
libblake_blake2s_force_update(struct libblake_blake2s_state *state, const void *data_, size_t len)
{
	const unsigned char *data = data_;
	size_t off = 0;

	for (; len - off >= 64; off += 64) {
		/* The following optimisations have been tested:
		 * 
		 * 1)
		 *     `*(uint64_t *)state->t += 64;`
		 *     result: slower
		 * 
		 * 2)
		 *     using `__builtin_add_overflow`
		 *     result: no difference
		 * 
		 * These testes where preformed on amd64 with a compile-time
		 * assumption that `UINT_LEAST32_C(0xFFFFffff) + 1 == 0`,
		 * which the compiler accepted and those included the attempted
		 * optimisations.
		 * 
		 * UNLIKELY does not seem to make any difference, but it
		 * does change the output, theoretically of the better.
		 */
		state->t[0] = (state->t[0] + 64) & UINT_LEAST32_C(0xFFFFffff);
		if (state->t[0] < 64)
			state->t[1] = (state->t[1] + 1) & UINT_LEAST32_C(0xFFFFffff);

		libblake_internal_blake2s_compress(state, &data[off]);
	}

	return off;
}
