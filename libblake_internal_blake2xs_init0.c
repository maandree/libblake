/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_internal_blake2xs_init0(struct libblake_blake2xs_state *state, const struct libblake_blake2xs_params *params)
{
	state->b2s.h[0] = UINT_LEAST32_C(0x6A09E667);
	state->b2s.h[1] = UINT_LEAST32_C(0xBB67AE85);
	state->b2s.h[2] = UINT_LEAST32_C(0x3C6EF372);
	state->b2s.h[3] = UINT_LEAST32_C(0xA54FF53A);
	state->b2s.h[4] = UINT_LEAST32_C(0x510E527F);
	state->b2s.h[5] = UINT_LEAST32_C(0x9B05688C);
	state->b2s.h[6] = UINT_LEAST32_C(0x1F83D9AB);
	state->b2s.h[7] = UINT_LEAST32_C(0x5BE0CD19);

	state->b2s.t[0] = 0;
	state->b2s.t[1] = 0;
	state->b2s.f[0] = 0;
	state->b2s.f[1] = 0;

	state->b2s.h[0] ^= ((uint_least32_t)params->digest_len & 255) << 0;
	state->b2s.h[0] ^= ((uint_least32_t)params->key_len & 255) << 8;
	state->b2s.h[0] ^= ((uint_least32_t)params->fanout & 255) << 16;
	state->b2s.h[0] ^= ((uint_least32_t)params->depth & 255) << 24;
	state->b2s.h[1] ^= params->leaf_len & UINT_LEAST32_C(0xFFFFffff);
	state->b2s.h[2] ^= params->node_offset & UINT_LEAST32_C(0xFFFFffff);
	state->b2s.h[3] ^= (uint_least32_t)(params->xof_len & UINT_LEAST16_C(0xFFFF)) << 0;
	state->b2s.h[3] ^= ((uint_least32_t)params->node_depth & 255) << 16;
	state->b2s.h[3] ^= ((uint_least32_t)params->inner_len & 255) << 24;
	state->b2s.h[4] ^= ((uint_least32_t)params->salt[0] & 255) << 0;
	state->b2s.h[4] ^= ((uint_least32_t)params->salt[1] & 255) << 8;
	state->b2s.h[4] ^= ((uint_least32_t)params->salt[2] & 255) << 16;
	state->b2s.h[4] ^= ((uint_least32_t)params->salt[3] & 255) << 24;
	state->b2s.h[5] ^= ((uint_least32_t)params->salt[4] & 255) << 0;
	state->b2s.h[5] ^= ((uint_least32_t)params->salt[5] & 255) << 8;
	state->b2s.h[5] ^= ((uint_least32_t)params->salt[6] & 255) << 16;
	state->b2s.h[5] ^= ((uint_least32_t)params->salt[7] & 255) << 24;
	state->b2s.h[6] ^= ((uint_least32_t)params->pepper[0] & 255) << 0;
	state->b2s.h[6] ^= ((uint_least32_t)params->pepper[1] & 255) << 8;
	state->b2s.h[6] ^= ((uint_least32_t)params->pepper[2] & 255) << 16;
	state->b2s.h[6] ^= ((uint_least32_t)params->pepper[3] & 255) << 24;
	state->b2s.h[7] ^= ((uint_least32_t)params->pepper[4] & 255) << 0;
	state->b2s.h[7] ^= ((uint_least32_t)params->pepper[5] & 255) << 8;
	state->b2s.h[7] ^= ((uint_least32_t)params->pepper[6] & 255) << 16;
	state->b2s.h[7] ^= ((uint_least32_t)params->pepper[7] & 255) << 24;
}
