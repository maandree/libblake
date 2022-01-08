/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake2xb_digest(const struct libblake_blake2xb_state *state,
                         uint_least32_t i /* start 0, increase by 1 until i * 64 >= desired hash length */,
                         uint_least8_t len /* desired hash MIN(length - i * 64, 64) */,
                         unsigned char output[static len] /* output for hash offset by i * 64 */)
{
	struct libblake_blake2xb_state xstate;
	struct libblake_blake2xb_params xparams;

	xparams = state->xof_params;
	xparams.node_offset = i;
	xparams.digest_len = len;

	libblake_internal_blake2xb_init0(&xstate, &xparams);

	xstate.b2b.f[0] = UINT_LEAST64_C(0xFFFFffffFFFFffff);
	xstate.b2b.t[0] = (uint_least64_t)state->xof_params.digest_len & UINT_LEAST64_C(0xFFFFffffFFFFffff);
	libblake_internal_blake2b_compress(&xstate.b2b, state->intermediate);
	libblake_internal_blake2b_output_digest(&xstate.b2b, (size_t)len, output);
}
