/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake224_init(struct libblake_blake224_state *state)
{
	state->s.h[0] = UINT_LEAST32_C(0xC1059ED8);
	state->s.h[1] = UINT_LEAST32_C(0x367CD507);
	state->s.h[2] = UINT_LEAST32_C(0x3070DD17);
	state->s.h[3] = UINT_LEAST32_C(0xF70E5939);
	state->s.h[4] = UINT_LEAST32_C(0xFFC00B31);
	state->s.h[5] = UINT_LEAST32_C(0x68581511);
	state->s.h[6] = UINT_LEAST32_C(0x64F98FA7);
	state->s.h[7] = UINT_LEAST32_C(0xBEFA4FA4);
	memset(state->s.s, 0, sizeof(state->s.s));
	memset(state->s.t, 0, sizeof(state->s.t));
}
