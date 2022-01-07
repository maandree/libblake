/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake512_init2(struct libblake_blake512_state *state, uint_least8_t salt[32])
{
	size_t i;
	state->b.h[0] = UINT_LEAST64_C(0x6A09E667F3BCC908);
	state->b.h[1] = UINT_LEAST64_C(0xBB67AE8584CAA73B);
	state->b.h[2] = UINT_LEAST64_C(0x3C6EF372FE94F82B);
	state->b.h[3] = UINT_LEAST64_C(0xA54FF53A5F1D36F1);
	state->b.h[4] = UINT_LEAST64_C(0x510E527FADE682D1);
	state->b.h[5] = UINT_LEAST64_C(0x9B05688C2B3E6C1F);
	state->b.h[6] = UINT_LEAST64_C(0x1F83D9ABFB41BD6B);
	state->b.h[7] = UINT_LEAST64_C(0x5BE0CD19137E2179);
	if (!salt) {
		memset(state->b.s, 0, sizeof(state->b.s));
	} else {
		for (i = 0; i < 4; i++) {
			state->b.s[i] = ((uint_least64_t)(salt[i * 8 + 0] & 255) << 56)
			              | ((uint_least64_t)(salt[i * 8 + 1] & 255) << 48)
			              | ((uint_least64_t)(salt[i * 8 + 2] & 255) << 40)
			              | ((uint_least64_t)(salt[i * 8 + 3] & 255) << 32)
			              | ((uint_least64_t)(salt[i * 8 + 4] & 255) << 24)
			              | ((uint_least64_t)(salt[i * 8 + 5] & 255) << 16)
			              | ((uint_least64_t)(salt[i * 8 + 6] & 255) <<  8)
			              | ((uint_least64_t)(salt[i * 8 + 7] & 255) <<  0);
		}
	}
	memset(state->b.t, 0, sizeof(state->b.t));
}
