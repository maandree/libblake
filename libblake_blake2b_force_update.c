/* See LICENSE file for copyright and license details. */
#include "common.h"

size_t
libblake_blake2b_force_update(struct libblake_blake2b_state *state, const void *data_, size_t len)
{
	const unsigned char *data = data_;
	size_t off = 0;

	for (; len - off >= 128; off += 128) {
		/* The following optimisations have been tested:
		 * 
		 * 1)
		 *     `*(__uint128_t *)state->t += 128;`
		 *     result: slower
		 * 
		 * 2)
		 *     addq, adcq using `__asm__ __volatile__`
		 *     result: slower (as 1)
		 * 
		 * 3)
		 *     using `__builtin_add_overflow`
		 *     result: no difference
		 * 
		 * These testes where preformed on amd64 with a compile-time
		 * assumption that `UINT_LEAST64_C(0xFFFFffffFFFFffff) + 1 == 0`,
		 * which the compiler accepted and those included the attempted
		 * optimisations.
		 * 
		 * UNLIKELY does not seem to make any difference, but it
		 * does change the output, theoretically of the better.
		 */
		state->t[0] = (state->t[0] + 128) & UINT_LEAST64_C(0xFFFFffffFFFFffff);
		if (UNLIKELY(state->t[0] < 128))
			state->t[1] = (state->t[1] + 1) & UINT_LEAST64_C(0xFFFFffffFFFFffff);

		libblake_internal_blake2b_compress(state, &data[off]);
	}

	return off;
}
