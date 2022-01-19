/* See LICENSE file for copyright and license details. */
#include "common.h"

static void
encode_uint64_le(unsigned char *out, uint_least64_t value, size_t bytes)
{
	/* Adding LIKELY to indicate that the default case is the
	 * expected does not affact the output */
	switch (bytes) {
	default:
		/*
		 * The following optimisation have been tested:
		 * 
		 * 1) Changing the default case, on amd64, to
		 *    *(uint64_t *)out = (uint64_t)value;
		 *    break;
		 *    result: halved performance
		 */
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
libblake_internal_blake2b_output_digest(struct libblake_blake2b_state *state, size_t output_len, unsigned char *output)
{
	size_t i, j;

#ifdef LITTLE_ENDIAN
	if (CODE_KILLER((uint_least64_t)(UINT_LEAST64_C(0xFFFFffffFFFFffff) + 1) == 0)) {
		/* 37.5x performance improvement;
		 * even though the compiler is smart enough to optimise
		 * `encode_uint64_le(&output[i], state->h[j], 8);` to a
		 * movq (on amd64), it is note smart enough to optimise
		 * the rest */
		memcpy(output, state->h, output_len);
		return;
	}
#endif

	/* Estimated to have similar performance benefit as above
	 * on big-endian machines */
	for (i = 0, j = 0; i + 8 < output_len; i += 8, j += 1)
		encode_uint64_le(&output[i], state->h[j], 8);
	encode_uint64_le(&output[i], state->h[j], output_len - i);

	/*
	 * Unoptimised code:
	 * 
	 * for (i = 0, j = 0; i < output_len; i += 8, j += 1)
	 *          encode_uint64_le(&output[i], state->h[j], output_len - i);
	 */
}
