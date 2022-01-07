/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake224_init(struct libblake_blake224_state *state)
{
	libblake_blake224_init2(state, NULL);
}
