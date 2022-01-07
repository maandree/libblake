/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake384_init(struct libblake_blake384_state *state)
{
	libblake_blake384_init2(state, NULL);
}
