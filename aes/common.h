/**
 * @file common.h
 * @author Jakob G. Maier <e11809618@student.tuwien.ac.at>
 * @date 10.01.2020 
 */
#ifndef COMMON_H__
#define COMMON_H__

#include <stdint.h>

#define AES_128

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

void _print(int round, char *step, uint8_t *data);
void _print_s(int round, char *step, uint8_t data[][Nb]);
void _print_state(uint8_t state[][Nb], int len);
void _print_w(int n, uint8_t *word);
void _print_l(uint8_t *word, int n);
void _print_word(int i, int n, uint8_t *w);
void error_exit(char *msg);

#endif /* COMMON_H__ */