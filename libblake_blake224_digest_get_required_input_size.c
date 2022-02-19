/* See LICENSE file for copyright and license details. */
#include "common.h"

size_t
libblake_blake224_digest_get_required_input_size(size_t len, size_t bits, const char *suffix)
{
	bits += suffix ? strlen(suffix) : 0;
	len += bits >> 3;
	bits &= 7;
	bits += (len & 63) << 3;
	len &= ~(size_t)63;
	len += (size_t)64 << (bits >= 512 - (1 + 2 * 32));
	return len;
}
