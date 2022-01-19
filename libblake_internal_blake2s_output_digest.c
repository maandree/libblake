/* See LICENSE file for copyright and license details. */
#include "common.h"

static void
encode_uint32_le(unsigned char *out, uint_least32_t value, size_t bytes)
{
	/* Adding LIKELY to indicate that the default case is the
	 * expected does not affact the output */
	switch (bytes) {
	default:
		/*
		 * The following optimisation have been tested:
		 * 
		 * 1) Changing the default case, on amd64, to
		 *    *(uint32_t *)out = (uint32_t)value;
		 *    break;
		 *    result: halved performance
		 */
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
libblake_internal_blake2s_output_digest(struct libblake_blake2s_state *state, size_t output_len, unsigned char *output)
{
	size_t i, j;

#ifdef LITTLE_ENDIAN
	if ((uint_least32_t)(UINT_LEAST32_C(0xFFFFffff) + 1) == 0) {
		/* No noticeable performance benefit on amd64, however
		 * it signficantly reduces the translation size and
		 * a 37.5x performance benefit was seen on the 64-bit
		 * version on amd64;
		 * even though the compiler is smart enough to optimise
		 * `encode_uint32_le(&output[i], state->h[j], 4);` to a
		 * movq (on amd64), it is note smart enough to optimise
		 * the rest */
		memcpy(output, state->h, output_len);
		return;
	}
#endif

	/* Estimated to have similar performance benefit as above
	 * on big-endian machines */
	for (i = 0, j = 0; i + 4 < output_len; i += 4, j += 1)
		encode_uint32_le(&output[i], state->h[j], 4);
	encode_uint32_le(&output[i], state->h[j], output_len - i);

	/*
	 * Unoptimised code:
	 * 
	 * for (i = 0, j = 0; i < output_len; i += 4, j += 1)
	 *         encode_uint32_le(&output[i], state->h[j], output_len - i);
	 */
}
