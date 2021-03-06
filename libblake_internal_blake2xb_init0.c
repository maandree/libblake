/* See LICENSE file for copyright and license details. */
#include "common.h"

#if defined(LITTLE_ENDIAN)
# define le64(X) X
#else
static uint_least64_t
le64(uint_least64_t h)
{
	unsigned char r[8];
	r[0] = (unsigned char)((h >>  0) & 255);
	r[1] = (unsigned char)((h >>  8) & 255);
	r[2] = (unsigned char)((h >> 16) & 255);
	r[3] = (unsigned char)((h >> 24) & 255);
	r[4] = (unsigned char)((h >> 32) & 255);
	r[5] = (unsigned char)((h >> 40) & 255);
	r[6] = (unsigned char)((h >> 48) & 255);
	r[7] = (unsigned char)((h >> 56) & 255);
	return *(uint_least64_t *)r;
}
#endif

void
libblake_internal_blake2xb_init0(struct libblake_blake2xb_state *state, const struct libblake_blake2xb_params *params)
{
	state->b2b.h[0] = UINT_LEAST64_C(0x6A09E667F3BCC908);
	state->b2b.h[1] = UINT_LEAST64_C(0xBB67AE8584CAA73B);
	state->b2b.h[2] = UINT_LEAST64_C(0x3C6EF372FE94F82B);
	state->b2b.h[3] = UINT_LEAST64_C(0xA54FF53A5F1D36F1);
	state->b2b.h[4] = UINT_LEAST64_C(0x510E527FADE682D1);
	state->b2b.h[5] = UINT_LEAST64_C(0x9B05688C2B3E6C1F);
	state->b2b.h[6] = UINT_LEAST64_C(0x1F83D9ABFB41BD6B);
	state->b2b.h[7] = UINT_LEAST64_C(0x5BE0CD19137E2179);

	state->b2b.t[0] = 0;
	state->b2b.t[1] = 0;
	state->b2b.f[0] = 0;
	state->b2b.f[1] = 0;

	if (CODE_KILLER(offsetof(struct libblake_blake2xb_params, inner_len) == 17)) {
#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wcast-align"
#endif
		state->b2b.h[0] ^= le64(((const uint_least64_t *)params)[0]);
		state->b2b.h[1] ^= le64(((const uint_least64_t *)params)[1]);
		state->b2b.h[2] ^= le64(((uint_least64_t)params->node_depth << 0) |
		                        ((uint_least64_t)params->inner_len << 8));
		state->b2b.h[4] ^= le64(*(const uint_least64_t *)&params->salt[0]);
		state->b2b.h[5] ^= le64(*(const uint_least64_t *)&params->salt[8]);
		state->b2b.h[6] ^= le64(*(const uint_least64_t *)&params->pepper[0]);
		state->b2b.h[7] ^= le64(*(const uint_least64_t *)&params->pepper[8]);
#if defined(__clang__)
# pragma clang diagnostic pop
#endif
	} else {
		state->b2b.h[0] ^= ((uint_least64_t)params->digest_len & 255) << 0;
		state->b2b.h[0] ^= ((uint_least64_t)params->key_len & 255) << 8;
		state->b2b.h[0] ^= ((uint_least64_t)params->fanout & 255) << 16;
		state->b2b.h[0] ^= ((uint_least64_t)params->depth & 255) << 24;
		state->b2b.h[0] ^= (uint_least64_t)(params->leaf_len & UINT_LEAST32_C(0xFFFFffff)) << 32;
		state->b2b.h[1] ^= (uint_least64_t)(params->node_offset & UINT_LEAST32_C(0xFFFFffff)) << 0;
		state->b2b.h[1] ^= (uint_least64_t)(params->xof_len & UINT_LEAST32_C(0xFFFFffff)) << 32;
		state->b2b.h[2] ^= ((uint_least64_t)params->node_depth & 255) << 0;
		state->b2b.h[2] ^= ((uint_least64_t)params->inner_len & 255) << 8;
		state->b2b.h[4] ^= ((uint_least64_t)params->salt[0] & 255) << 0;
		state->b2b.h[4] ^= ((uint_least64_t)params->salt[1] & 255) << 8;
		state->b2b.h[4] ^= ((uint_least64_t)params->salt[2] & 255) << 16;
		state->b2b.h[4] ^= ((uint_least64_t)params->salt[3] & 255) << 24;
		state->b2b.h[4] ^= ((uint_least64_t)params->salt[4] & 255) << 32;
		state->b2b.h[4] ^= ((uint_least64_t)params->salt[5] & 255) << 40;
		state->b2b.h[4] ^= ((uint_least64_t)params->salt[6] & 255) << 48;
		state->b2b.h[4] ^= ((uint_least64_t)params->salt[7] & 255) << 56;
		state->b2b.h[5] ^= ((uint_least64_t)params->salt[8] & 255) << 0;
		state->b2b.h[5] ^= ((uint_least64_t)params->salt[9] & 255) << 8;
		state->b2b.h[5] ^= ((uint_least64_t)params->salt[A] & 255) << 16;
		state->b2b.h[5] ^= ((uint_least64_t)params->salt[B] & 255) << 24;
		state->b2b.h[5] ^= ((uint_least64_t)params->salt[C] & 255) << 32;
		state->b2b.h[5] ^= ((uint_least64_t)params->salt[D] & 255) << 40;
		state->b2b.h[5] ^= ((uint_least64_t)params->salt[E] & 255) << 48;
		state->b2b.h[5] ^= ((uint_least64_t)params->salt[F] & 255) << 56;
		state->b2b.h[6] ^= ((uint_least64_t)params->pepper[0] & 255) << 0;
		state->b2b.h[6] ^= ((uint_least64_t)params->pepper[1] & 255) << 8;
		state->b2b.h[6] ^= ((uint_least64_t)params->pepper[2] & 255) << 16;
		state->b2b.h[6] ^= ((uint_least64_t)params->pepper[3] & 255) << 24;
		state->b2b.h[6] ^= ((uint_least64_t)params->pepper[4] & 255) << 32;
		state->b2b.h[6] ^= ((uint_least64_t)params->pepper[5] & 255) << 40;
		state->b2b.h[6] ^= ((uint_least64_t)params->pepper[6] & 255) << 48;
		state->b2b.h[6] ^= ((uint_least64_t)params->pepper[7] & 255) << 56;
		state->b2b.h[7] ^= ((uint_least64_t)params->pepper[8] & 255) << 0;
		state->b2b.h[7] ^= ((uint_least64_t)params->pepper[9] & 255) << 8;
		state->b2b.h[7] ^= ((uint_least64_t)params->pepper[A] & 255) << 16;
		state->b2b.h[7] ^= ((uint_least64_t)params->pepper[B] & 255) << 24;
		state->b2b.h[7] ^= ((uint_least64_t)params->pepper[C] & 255) << 32;
		state->b2b.h[7] ^= ((uint_least64_t)params->pepper[D] & 255) << 40;
		state->b2b.h[7] ^= ((uint_least64_t)params->pepper[E] & 255) << 48;
		state->b2b.h[7] ^= ((uint_least64_t)params->pepper[F] & 255) << 56;
	}
}
