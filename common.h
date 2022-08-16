/**
 * @file common.h
 * @author Jakob G. Maier <e11809618@student.tuwien.ac.at>
 * @date 31.03.2020
 */
#ifndef COMMON_H__
#define COMMON_H__

#include <stdint.h>

#define Nb      (4)     /* length state */
#define BLOCK_LENGTH    (Nb * Nb) /* standard block size, in bytes (128 bit) */
#define WORD            (4)     /* standard word size (bytes) */

extern const uint8_t s_box[16][16];
extern const uint8_t inv_s_box[16][16];
extern const uint8_t Rcon[11];

void _print(const uint8_t *data);
void _print_r(const int round, const char *step, const uint8_t *data);
void _print_s(const int round, const char *step, const uint8_t data[Nb][Nb]);
void _print_w(const int i, const uint8_t *w);
void error_exit(char *msg);
void read_hex(char *hex, uint8_t *buf, size_t bytes);

typedef struct {
    uint8_t key[16];
    uint8_t iv[16];
} aes_128_cbc_key_t;

#endif /* COMMON_H__ */