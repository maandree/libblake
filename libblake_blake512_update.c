/* See LICENSE file for copyright and license details. */
#include "common.h"

size_t
libblake_blake512_update(struct libblake_blake512_state *state, const void *data, size_t len)
{
	return libblake_internal_blakeb_update(&state->b, data, len);
}
