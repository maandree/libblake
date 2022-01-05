/* See LICENSE file for copyright and license details. */
#include "common.h"

size_t
libblake_blake384_update(struct libblake_blake384_state *state, const void *data, size_t len)
{
	return libblake_internal_blakeb_update(&state->b, data, len);
}
