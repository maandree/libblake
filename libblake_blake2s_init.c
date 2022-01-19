/* See LICENSE file for copyright and license details. */
#include "common.h"

#if defined(LITTLE_ENDIAN)
# define le32(X) X
#else
static uint_least32_t
le32(uint_least32_t h)
{
	unsigned char r[4];
	r[0] = (unsigned char)((h >>  0) & 255);
	r[1] = (unsigned char)((h >>  8) & 255);
	r[2] = (unsigned char)((h >> 16) & 255);
	r[3] = (unsigned char)((h >> 24) & 255);
	return *(uint_least32_t *)r;
}
#endif

void
libblake_blake2s_init(struct libblake_blake2s_state *state, const struct libblake_blake2s_params *params, const unsigned char *key)
{
	state->h[0] = UINT_LEAST32_C(0x6A09E667);
	state->h[1] = UINT_LEAST32_C(0xBB67AE85);
	state->h[2] = UINT_LEAST32_C(0x3C6EF372);
	state->h[3] = UINT_LEAST32_C(0xA54FF53A);
	state->h[4] = UINT_LEAST32_C(0x510E527F);
	state->h[5] = UINT_LEAST32_C(0x9B05688C);
	state->h[6] = UINT_LEAST32_C(0x1F83D9AB);
	state->h[7] = UINT_LEAST32_C(0x5BE0CD19);

	state->t[0] = 0;
	state->t[1] = 0;
	state->f[0] = 0;
	state->f[1] = 0;

	if (CODE_KILLER(offsetof(struct libblake_blake2s_params, inner_len) == 17)) {
#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wcast-align"
#endif
		state->h[0] ^= le32(((const uint_least32_t *)params)[0]);
		state->h[1] ^= le32(((const uint_least32_t *)params)[1]);
		state->h[2] ^= le32((uint_least32_t)(params->node_offset >> 0));
		state->h[3] ^= le32(((uint_least32_t)(params->node_offset >> 32) & UINT_LEAST32_C(0xFFFF)) |
		                    ((uint_least32_t)params->node_depth << 16) |
		                    ((uint_least32_t)params->inner_len << 24));
		state->h[4] ^= le32(*(const uint_least32_t *)&params->salt[0]);
		state->h[5] ^= le32(*(const uint_least32_t *)&params->salt[4]);
		state->h[6] ^= le32(*(const uint_least32_t *)&params->pepper[0]);
		state->h[7] ^= le32(*(const uint_least32_t *)&params->pepper[4]);
#if defined(__clang__)
# pragma clang diagnostic pop
#endif
	} else {
		state->h[0] ^= ((uint_least32_t)params->digest_len & 255) << 0;
		state->h[0] ^= ((uint_least32_t)params->key_len & 255) << 8;
		state->h[0] ^= ((uint_least32_t)params->fanout & 255) << 16;
		state->h[0] ^= ((uint_least32_t)params->depth & 255) << 24;
		state->h[1] ^= params->leaf_len & UINT_LEAST32_C(0xFFFFffff);
		state->h[2] ^= (uint_least32_t)((params->node_offset >> 0) & UINT_LEAST64_C(0xFFFFffff));
		state->h[3] ^= (uint_least32_t)((params->node_offset >> 32) & UINT_LEAST64_C(0xFFFF)) << 0;
		state->h[3] ^= ((uint_least32_t)params->node_depth & 255) << 16;
		state->h[3] ^= ((uint_least32_t)params->inner_len & 255) << 24;
		state->h[4] ^= ((uint_least32_t)params->salt[0] & 255) << 0;
		state->h[4] ^= ((uint_least32_t)params->salt[1] & 255) << 8;
		state->h[4] ^= ((uint_least32_t)params->salt[2] & 255) << 16;
		state->h[4] ^= ((uint_least32_t)params->salt[3] & 255) << 24;
		state->h[5] ^= ((uint_least32_t)params->salt[4] & 255) << 0;
		state->h[5] ^= ((uint_least32_t)params->salt[5] & 255) << 8;
		state->h[5] ^= ((uint_least32_t)params->salt[6] & 255) << 16;
		state->h[5] ^= ((uint_least32_t)params->salt[7] & 255) << 24;
		state->h[6] ^= ((uint_least32_t)params->pepper[0] & 255) << 0;
		state->h[6] ^= ((uint_least32_t)params->pepper[1] & 255) << 8;
		state->h[6] ^= ((uint_least32_t)params->pepper[2] & 255) << 16;
		state->h[6] ^= ((uint_least32_t)params->pepper[3] & 255) << 24;
		state->h[7] ^= ((uint_least32_t)params->pepper[4] & 255) << 0;
		state->h[7] ^= ((uint_least32_t)params->pepper[5] & 255) << 8;
		state->h[7] ^= ((uint_least32_t)params->pepper[6] & 255) << 16;
		state->h[7] ^= ((uint_least32_t)params->pepper[7] & 255) << 24;
	}

	if (params->key_len) {
		state->t[0] = 32;
		libblake_internal_blake2s_compress(state, key);
	}
}
