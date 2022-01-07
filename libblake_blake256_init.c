/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake256_init(struct libblake_blake256_state *state)
{
	libblake_blake256_init2(state, NULL);
}
