/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_encode_hex(const void *data_, size_t n, char out[/* static n * 2 + 1 */], int uppercase)
{
	const char *digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
	const unsigned char *data = data_;
	size_t i, j;

	for (j = 0, i = 0; i < n; i += 1) {
		out[j++] = digits[(data[i] >> 4) & 15];
		out[j++] = digits[(data[i] >> 0) & 15];
	}
	out[n * 2] = '\0';
}
