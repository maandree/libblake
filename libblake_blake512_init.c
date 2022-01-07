/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake512_init(struct libblake_blake512_state *state)
{
	libblake_blake512_init2(state, NULL);
}
