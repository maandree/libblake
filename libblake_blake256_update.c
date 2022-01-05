/* See LICENSE file for copyright and license details. */
#include "common.h"

size_t
libblake_blake256_update(struct libblake_blake256_state *state, const void *data, size_t len)
{
	return libblake_internal_blakes_update(&state->s, data, len);
}
