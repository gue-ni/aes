/**
 * @file common.h
 * @author Jakob G. Maier <e11809618@student.tuwien.ac.at>
 * @date 10.01.2020 
 */
#ifndef COMMON_H__
#define COMMON_H__

#include <stdint.h>

#define DEBUG   (1)

#define BLOCKSIZE (128)
#define SIZE (16)
#define Nb      (4)     /* length state*/
#define Nk      (4)     /* length cipher key (words)*/
#define Nr      (10)    /* number of rounds */
#define WORD    (4)     /* standard word size (bytes) */
#define Nke     (WORD * Nb * (Nr + 1)) /* Number of bytes in full key expansion */
#define Nrk     (Nk * WORD) /* length of round key in bytes) */

extern const uint8_t s_box[16][16];
extern const uint8_t Rcon[11];

void _print(int round, char *step, uint8_t *data);
void _print_s(int round, char *step, uint8_t data[][Nb]);
void _print_state(uint8_t state[][Nb], int len);
void _print_w(int n, uint8_t *word);
void _print_l(uint8_t *word, int n);
void _print_word(int i, int n, uint8_t *w);
void error_exit(char *msg);

#endif /* COMMON_H__ */