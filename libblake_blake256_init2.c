/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake256_init2(struct libblake_blake256_state *state, uint_least8_t salt[16])
{
	size_t i;
	state->s.h[0] = UINT_LEAST32_C(0x6A09E667);
	state->s.h[1] = UINT_LEAST32_C(0xBB67AE85);
	state->s.h[2] = UINT_LEAST32_C(0x3C6EF372);
	state->s.h[3] = UINT_LEAST32_C(0xA54FF53A);
	state->s.h[4] = UINT_LEAST32_C(0x510E527F);
	state->s.h[5] = UINT_LEAST32_C(0x9B05688C);
	state->s.h[6] = UINT_LEAST32_C(0x1F83D9AB);
	state->s.h[7] = UINT_LEAST32_C(0x5BE0CD19);
	if (!salt) {
		memset(state->s.s, 0, sizeof(state->s.s));
	} else {
		for (i = 0; i < 4; i++) {
			state->s.s[i] = ((uint_least32_t)(salt[i * 4 + 0] & 255) << 24)
			              | ((uint_least32_t)(salt[i * 4 + 1] & 255) << 16)
			              | ((uint_least32_t)(salt[i * 4 + 2] & 255) <<  8)
			              | ((uint_least32_t)(salt[i * 4 + 3] & 255) <<  0);
		}
	}
	memset(state->s.t, 0, sizeof(state->s.t));
}
