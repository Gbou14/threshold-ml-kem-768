#ifndef HEXUTIL_H
#define HEXUTIL_H

#include <stddef.h>
#include <stdint.h>

/* out must have room for 2*len + 1 bytes (including the terminator). */
void hex_encode(char *out, const uint8_t *in, size_t len);

/* Returns 0 on success, -1 if hex is malformed or the wrong length for
 * out_len bytes. */
int hex_decode(uint8_t *out, size_t out_len, const char *hex);

#endif /* HEXUTIL_H */
