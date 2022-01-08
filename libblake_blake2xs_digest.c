/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake2xs_digest(const struct libblake_blake2xs_state *state,
                         uint_least32_t i /* start 0, increase by 1 until i * 32 >= desired hash length */,
                         uint_least8_t len /* desired hash MIN(length - i * 32, 32) */,
                         unsigned char output[static len]  /* output for hash offset by i * 32 */)
{
	struct libblake_blake2xs_state xstate;
	struct libblake_blake2xs_params xparams;

	xparams = state->xof_params;
	xparams.node_offset = i;
	xparams.digest_len = len;

	libblake_internal_blake2xs_init0(&xstate, &xparams);

	xstate.b2s.f[0] = UINT_LEAST32_C(0xFFFFffff);
	xstate.b2s.t[0] = (uint_least32_t)state->xof_params.digest_len & UINT_LEAST32_C(0xFFFFffff);
	libblake_internal_blake2s_compress(&xstate.b2s, state->intermediate);
	libblake_internal_blake2s_output_digest(&xstate.b2s, (size_t)len, output);
}
