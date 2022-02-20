/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake2xs_init(struct libblake_blake2xs_state *state, const struct libblake_blake2xs_params *params)
{
	libblake_internal_blake2xs_init0(state, params);

	memcpy(&state->xof_params, params, sizeof(state->xof_params));
	state->xof_params.digest_len = 32;
	state->xof_params.key_len = 0;
	state->xof_params.fanout = 0;
	state->xof_params.depth = 0;
	state->xof_params.leaf_len = 32;
	state->xof_params.xof_len = params->xof_len;
	state->xof_params.node_depth = 0;
	state->xof_params.inner_len = 32;

	memset(&state->intermediate, 0, sizeof(state->intermediate));
}
