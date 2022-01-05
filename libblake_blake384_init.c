/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake384_init(struct libblake_blake384_state *state)
{
	state->b.h[0] = UINT_LEAST64_C(0xCBBB9D5DC1059ED8);
	state->b.h[1] = UINT_LEAST64_C(0x629A292A367CD507);
	state->b.h[2] = UINT_LEAST64_C(0x9159015A3070DD17);
	state->b.h[3] = UINT_LEAST64_C(0x152FECD8F70E5939);
	state->b.h[4] = UINT_LEAST64_C(0x67332667FFC00B31);
	state->b.h[5] = UINT_LEAST64_C(0x8EB44A8768581511);
	state->b.h[6] = UINT_LEAST64_C(0xDB0C2E0D64F98FA7);
	state->b.h[7] = UINT_LEAST64_C(0x47B5481DBEFA4FA4);
	memset(state->b.s, 0, sizeof(state->b.s));
	memset(state->b.t, 0, sizeof(state->b.t));
}
