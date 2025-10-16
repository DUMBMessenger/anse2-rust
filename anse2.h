#ifndef DUMB_API_H
#define DUMB_API_H

/* auto generated, do not edit */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void anse2_init_tables(void);

/**
 * encrypt: allocating buffer and returns it from out_ptr and out_len.
 * caller needed to call anse2_free_buffer for freeing.
 * error codes:
 * 0 = ok
 * 1 = null pointer (input or output or key)
 * 2 = allocation failure
 * 3 = invalid utf8 in key
 */
int anse2_encrypt_c(const uint8_t *input_ptr,
                    uintptr_t input_len,
                    const char *key_ptr,
                    uint8_t **out_ptr,
                    uintptr_t *out_len);

/**
 * decrypt: allocating buffer and returns it from out_ptr and out_len. (It's just a same as encrypt)
 */
int anse2_decrypt_c(const uint8_t *input_ptr,
                    uintptr_t input_len,
                    const char *key_ptr,
                    uint8_t **out_ptr,
                    uintptr_t *out_len);

/**
 * free buffer previously returned by encrypt/decrypt
 */
void anse2_free_buffer(uint8_t *buf_ptr, uintptr_t buf_len);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* DUMB_API_H */
