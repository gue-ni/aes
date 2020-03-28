/**
 * @file common.h
 * @author Jakob G. Maier <e11809618@student.tuwien.ac.at>
 * @date 10.01.2020 
 */
#ifndef COMMON_H__
#define COMMON_H__

#include <stdint.h>

#define AES_128 /* defines the key length */

#ifdef AES_128
#define Nk      (4)     /* length cipher key (32 bit words)*/
#define Nr      (10)    /* number of rounds */
#endif

#ifdef AES_192
#define Nk      (6)     /* length cipher key (32 bit words)*/
#define Nr      (12)    /* number of rounds */
#endif

#ifdef AES_256
#define Nk      (8)     /* length cipher key (32 bit words)*/
#define Nr      (14)    /* number of rounds */
#endif

#define Nb      (4)     /* length state */
#define BLOCK_LENGTH    (Nb * Nb) /* standard block size, in bytes (128 bit) */
#define WORD            (4)     /* standard word size (bytes) */

extern const uint8_t s_box[16][16];
extern const uint8_t inv_s_box[16][16];
extern const uint8_t Rcon[11];

void _print(const int round, const char *step, const uint8_t *data);
void _print_s(const int round, const char *step, const uint8_t data[Nb][Nb]);
void _print_word(const int i, const uint8_t *w);
void error_exit(char *msg);

typedef struct {
    uint8_t key[16];
    uint8_t iv[16];
    uint8_t plain[16];
    uint8_t cipher[16];
} test_vector;

#endif /* COMMON_H__ */