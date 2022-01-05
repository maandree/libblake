/* See LICENSE file for copyright and license details. */
#include "common.h"

size_t
libblake_blake224_digest_get_required_input_size(size_t len, size_t bits, const char *suffix)
{
	return libblake_blake256_digest_get_required_input_size(len, bits, suffix);
}
