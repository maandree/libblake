/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake2xb_init(struct libblake_blake2xb_state *state, const struct libblake_blake2xb_params *params, const unsigned char *key)
{
	libblake_internal_blake2xb_init0(state, params);

	memcpy(&state->xof_params, params, sizeof(state->xof_params));
	state->xof_params.key_len = 0;
	state->xof_params.fanout = 0;
	state->xof_params.depth = 0;
	state->xof_params.leaf_len = 64;
	state->xof_params.xof_len = params->xof_len;
	state->xof_params.node_depth = 0;
	state->xof_params.inner_len = 64;

	memset(&state->intermediate, 0, sizeof(state->intermediate));

	if (params->key_len) {
		state->b2b.t[0] = 128;
		libblake_internal_blake2b_compress(&state->b2b, key);
	}
}
