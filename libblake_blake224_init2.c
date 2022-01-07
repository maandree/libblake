/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake224_init2(struct libblake_blake224_state *state, uint_least8_t salt[16])
{
	size_t i;
	state->s.h[0] = UINT_LEAST32_C(0xC1059ED8);
	state->s.h[1] = UINT_LEAST32_C(0x367CD507);
	state->s.h[2] = UINT_LEAST32_C(0x3070DD17);
	state->s.h[3] = UINT_LEAST32_C(0xF70E5939);
	state->s.h[4] = UINT_LEAST32_C(0xFFC00B31);
	state->s.h[5] = UINT_LEAST32_C(0x68581511);
	state->s.h[6] = UINT_LEAST32_C(0x64F98FA7);
	state->s.h[7] = UINT_LEAST32_C(0xBEFA4FA4);
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
