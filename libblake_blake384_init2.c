/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake384_init2(struct libblake_blake384_state *state, const uint_least8_t salt[32])
{
	size_t i;
	state->b.h[0] = UINT_LEAST64_C(0xCBBB9D5DC1059ED8);
	state->b.h[1] = UINT_LEAST64_C(0x629A292A367CD507);
	state->b.h[2] = UINT_LEAST64_C(0x9159015A3070DD17);
	state->b.h[3] = UINT_LEAST64_C(0x152FECD8F70E5939);
	state->b.h[4] = UINT_LEAST64_C(0x67332667FFC00B31);
	state->b.h[5] = UINT_LEAST64_C(0x8EB44A8768581511);
	state->b.h[6] = UINT_LEAST64_C(0xDB0C2E0D64F98FA7);
	state->b.h[7] = UINT_LEAST64_C(0x47B5481DBEFA4FA4);
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
