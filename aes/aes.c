/**
 * @file aes.c
 * @author Jakob G. Maier <e11809618@student.tuwien.ac.at>
 * @date 10.01.2020
 * 
 * @brief A small implementation of the Advanced Encryption Standard 
 * 
 * TODO: 
 * CBC
 * PKCS#7
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

uint8_t PLAINTEXT[16]   = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; 
uint8_t KEY_128_1[16]   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
uint8_t KEY_128_2[16]   = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t KEY_256_1[32]   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
uint8_t KEY_256_2[32]   = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09 ,0x14, 0xdf, 0xf4 };
uint8_t OUT_128_1[16]   = { 0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A };

/*
uint8_t KEY[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t IV[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
uint8_t PLAIN[16] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
uint8_t CIPHER[16] = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d };
*/

uint8_t KEY[16] = { 0xc2, 0x86, 0x69, 0x6d, 0x88, 0x7c, 0x9a, 0xa0, 0x61, 0x1b, 0xbb, 0x3e, 0x20, 0x25, 0xa4, 0x5a};
uint8_t IV[16] = { 0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58};
uint8_t CIPHER[32] = { 0xd2, 0x96, 0xcd, 0x94, 0xc2, 0xcc, 0xcf, 0x8a, 0x3a, 0x86, 0x30, 0x28, 0xb5, 0xe1, 0xdc, 0x0a, 0x75, 0x86, 0x60, 0x2d, 0x25, 0x3c, 0xff, 0xf9, 0x1b, 0x82, 0x66, 0xbe, 0xa6, 0xd6, 0x1a, 0xb1 };
uint8_t PLAIN[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

/*
uint8_t KEY[16] = { 0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b, 0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06};
uint8_t IV[16] = { 0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30, 0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41};
uint8_t PLAIN[16] = { 0x22,0x53,0x69,0x6e,0x67,0x6c,0x65, 0x62,0x6c,0x6f,0x63,0x6b, 0x6d,0x73,0x67, 0x22};
uint8_t CIPHER[16] = { 0xe3, 0x53, 0x77, 0x9c, 0x10, 0x79, 0xae, 0xb8, 0x27, 0x08, 0x94, 0x2d, 0xbe, 0x77, 0x18, 0x1a};
*/


void SubWord(uint8_t *in){
    uint8_t tmp[4];
    memcpy(tmp, in, 4);
    for (int i = 0; i < 4; i++){
        in[i] = s_box[ tmp[i] >> 4 ][ tmp[i] & 0x0F];
    }
}

void RotWord(uint8_t *in){
    uint8_t tmp[4];
    memcpy(tmp, in, 4);
    in[0] = tmp[1];
    in[1] = tmp[2];
    in[2] = tmp[3];
    in[3] = tmp[0];
}

void KeyExpansion(const uint8_t key[], uint8_t w[]){
    uint8_t temp[4];
    uint8_t i = 0;
    memset(w, 0x0, BLOCK_LENGTH * (Nr + 1));

    while (i < Nk){
        for (int k = 0; k < 4;k++){
            w[4 * i + k] = key[4 * i + k];
        }
        i++;
    }

    i = Nk;
   
    while(i < Nb * (Nr + 1)){
        for (int k = 0; k < 4;k++){
            temp[k] = w[(i - 1) * 4 + k];
        }
#ifdef DEBUG
        _print_word(i, temp);
#endif

        if ( i % Nk == 0){
            RotWord(temp);
#ifdef DEBUG
            _print_word(i, temp);
#endif

            SubWord(temp);
#ifdef DEBUG
            _print_word(i, temp);
            printf("i: %02d %02X000000\n", i, Rcon[i/Nk]);
#endif
            temp[0] = temp[0] ^ Rcon[i/Nk];
#ifdef DEBUG
            _print_word(i, temp);
#endif

        } else if(Nk > 6 && i % Nk == 4){
            SubWord(temp);
#ifdef DEBUG
            _print_word(i, temp);
#endif
        } 

#ifdef DEBUG
        _print_word(i, w+(4 * (i-Nk)));
#endif
        for (int k = 0; k < 4;k++){
            w[4 * i + k] = w[4 * (i-Nk) + k] ^ temp[k];
        }

#ifdef DEBUG
        _print_word(i, w+4*i);
#endif

        i++;
    }
}

void SubBytes(uint8_t state[4][Nb]){
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++){
            state[i][j] = s_box[ state[i][j] >> 4 ][ state[i][j] & 0x0F];
        }
    }
}

void ShiftRows(uint8_t state[4][Nb]){
    uint8_t temp[4][Nb];
    for (int i = 0; i< 4; i++){
        memcpy(temp[i], state[i], 4);
    }

    for (int r = 1; r < 4; r++){
        for (int c = 0; c < 4; c++){
            state[c][r] = temp[ (c + r) % Nb][r];
        }
    }
}

uint8_t xtime(uint8_t x){
    return ((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

uint8_t multiply(uint8_t p, uint8_t q){
    uint8_t r = 0;
    for (int i = 0; i < 8; i++){
        if (q & 0x01){
            r ^= p;
        }
        p = xtime(p);
        q >>= 1;
    }
    return r;
}

void MixColumns(uint8_t state[4][Nb]){
    uint8_t temp[4][Nb];
    for (int i = 0; i< 4; i++) memcpy(temp[i], state[i], 4);

    for (int c = 0; c < 4; c++){
        state[c][0] = multiply(0x02, temp[c][0]) ^ multiply(0x03, temp[c][1]) ^ (temp[c][2]) ^ (temp[c][3]);
        state[c][1] = (temp[c][0]) ^ multiply(0x02, temp[c][1]) ^ multiply(0x03, temp[c][2]) ^ (temp[c][3]);
        state[c][2] = (temp[c][0]) ^ (temp[c][1]) ^ multiply(0x02, temp[c][2]) ^ multiply(0x03, temp[c][3]);
        state[c][3] = multiply(0x03, temp[c][0]) ^ (temp[c][1]) ^ (temp[c][2]) ^ multiply(0x02, temp[c][3]);
    }
}

void AddRoundKey(uint8_t state[4][Nb], const uint8_t *roundKey){
    int k = 0;
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++){
            state[i][j] = roundKey[k++] ^ state[i][j];
        }
    }
}

void InvShiftRows(uint8_t state[4][Nb]){
    uint8_t temp[4][Nb];
    for (int i = 0; i< 4; i++) memcpy(temp[i], state[i], 4);

    for (int r = 1; r < 4; r++){
        for (int c = 0; c < 4; c++){
            state[ (c + r) % Nb][r] = temp[c][r];
        }
    }
}

void InvSubBytes(uint8_t state[4][Nb]){
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++){
            state[i][j] = inv_s_box[ state[i][j] >> 4 ][ state[i][j] & 0x0F];
        }
    }
}

void InvMixColumns(uint8_t state[4][Nb]){
    uint8_t temp[4][Nb];
    for (int i = 0; i< 4; i++) memcpy(temp[i], state[i], 4);

    for (int c = 0; c < 4; c++){
        state[c][0] = multiply(0x0e, temp[c][0]) ^ multiply(0x0b, temp[c][1]) ^ multiply(0x0d, temp[c][2]) ^ multiply(0x09, temp[c][3]);
        state[c][1] = multiply(0x09, temp[c][0]) ^ multiply(0x0e, temp[c][1]) ^ multiply(0x0b, temp[c][2]) ^ multiply(0x0d, temp[c][3]);
        state[c][2] = multiply(0x0d, temp[c][0]) ^ multiply(0x09, temp[c][1]) ^ multiply(0x0e, temp[c][2]) ^ multiply(0x0b, temp[c][3]);
        state[c][3] = multiply(0x0b, temp[c][0]) ^ multiply(0x0d, temp[c][1]) ^ multiply(0x09, temp[c][2]) ^ multiply(0x0e, temp[c][3]);
    }
}  

void AES_InvCipher(const uint8_t *in, uint8_t *out, const uint8_t *w){
    uint8_t state[4][Nb];
    int i, j, k = 0, rp = 1;

    for (i = 0; i < 4; i++){
        for (j = 0; j < Nb; j++){
            state[i][j] = in[k++];
        }
    }
#ifdef DEBUG
    _print_s(rp, "iinput", state);
    _print(rp, "ik_sch", w+(Nr*BLOCK_LENGTH));
#endif
    AddRoundKey(state, w+(Nr*BLOCK_LENGTH));
    
    for (int round = Nr-1; round > 0; round--){
#ifdef DEBUG
        _print_s(rp, "istart", state);
#endif
        InvShiftRows(state);
#ifdef DEBUG
        _print_s(rp, "is_row", state);
#endif
        InvSubBytes(state);
#ifdef DEBUG
        _print_s(rp, "is_box", state);
        _print(rp, "ik_sch", w+round*BLOCK_LENGTH);
#endif
        AddRoundKey(state, w+round*BLOCK_LENGTH);
#ifdef DEBUG
        _print_s(rp, "ik_add", state);
#endif
        InvMixColumns(state);
        rp++;
    }

    InvShiftRows(state);
#ifdef DEBUG
    _print_s(rp, "is_row", state);
#endif
    InvSubBytes(state);
#ifdef DEBUG
    _print_s(rp, "is_box", state);
    _print(rp, "ik_sch", w);
#endif
    AddRoundKey(state, w);

    k = 0;
    for (i = 0; i < 4; i++){
        for (j = 0; j < Nb; j++){
            out[k++] = state[i][j];
        }
    }
#ifdef DEBUG
    _print(rp, "ioutput", out);
#endif
}

void AES_Cipher(const uint8_t *in, uint8_t *out, const uint8_t *w){
    uint8_t state[4][Nb];
    int round = 0;
#ifdef DEBUG
    _print(round, "input", in);
#endif
    
    int i, j, k = 0;
    for (i = 0; i < 4; i++){
        for (j = 0; j < Nb; j++){
            state[i][j] = in[k++];
        }
    }
    
#ifdef DEBUG
    _print(round, "k_sch", w);
#endif
    AddRoundKey(state, w+(round*BLOCK_LENGTH));

    for (round = 1; round < Nr; round++){
#ifdef DEBUG
        _print_s(round, "start", state);
#endif
        SubBytes(state);
#ifdef DEBUG
        _print_s(round, "s_box", state);
#endif
        ShiftRows(state);
#ifdef DEBUG
        _print_s(round, "s_row", state);
#endif
        MixColumns(state);
#ifdef DEBUG
        _print_s(round, "m_col", state);
        _print(round, "k_sch", w+round*BLOCK_LENGTH);
#endif
        AddRoundKey(state, w+round*BLOCK_LENGTH);
    }

    SubBytes(state);
#ifdef DEBUG
    _print_s(round, "s_box", state);
#endif
    ShiftRows(state);
#ifdef DEBUG
    _print_s(round, "s_row", state);
    _print(round, "k_sch", w+round*BLOCK_LENGTH);
#endif
    AddRoundKey(state, w+round*BLOCK_LENGTH);

    k = 0;
    for (i = 0; i < 4; i++){
        for (j = 0; j < Nb; j++){
            out[k++] = state[i][j];
        }
    }

#ifdef DEBUG
    _print(round, "output", out);
#endif
}

void XOR_block(uint8_t *a, uint8_t *b, uint8_t *out){
    for (int i = 0; i < BLOCK_LENGTH; i++){
        out[i] = a[i] ^ b[i];
    }
}

void AES_CBC_Cipher(uint8_t *in, uint8_t *out, const int n, const uint8_t *w, const uint8_t *iv){
    uint8_t prev[BLOCK_LENGTH];
    uint8_t temp[BLOCK_LENGTH];

    memcpy(prev, iv, BLOCK_LENGTH);

    for (int i = 0; i < n; i++){
        XOR_block(in+(i * BLOCK_LENGTH), prev, temp);
        AES_Cipher(temp, out+(i * BLOCK_LENGTH), w);
        memcpy(prev, out+(i * BLOCK_LENGTH), BLOCK_LENGTH);
    }
}

void AES_CBC_InvCipher(uint8_t *in, uint8_t *out, int n, uint8_t *w, uint8_t *iv){
    uint8_t prev[BLOCK_LENGTH];
    uint8_t temp[BLOCK_LENGTH];

    memcpy(prev, iv, BLOCK_LENGTH);

    for (int i = 0; i < n; i++){
        if (i > 0) memcpy(prev, in+(i * BLOCK_LENGTH), BLOCK_LENGTH);
        AES_InvCipher(in+(i * BLOCK_LENGTH), temp, w);
        XOR_block(temp, prev, out+(i * BLOCK_LENGTH));
    }
}

int main(void){
    uint8_t w[BLOCK_LENGTH * (Nr + 1)];
    uint8_t OUT[16];
   
    printf("AES-%d (Nk=%d, Nr=%d)\n", Nk*32, Nk, Nr);

    KeyExpansion(KEY_128_1, w);
    AES_Cipher(PLAINTEXT, OUT, w);
    if (memcmp(OUT, OUT_128_1, BLOCK_LENGTH) != 0){
        error_exit("AES_Cipher IS NOT CORRECT");
    }
    AES_InvCipher(OUT, OUT, w);
    if (memcmp(OUT, PLAINTEXT, BLOCK_LENGTH) != 0){
        error_exit("AES_InvCipher IS NOT CORRECT");
    }
    printf("AES-128 is correct\n");

    KeyExpansion(KEY, w);
    AES_CBC_Cipher(PLAIN, OUT, 2, w, IV);
    if (memcmp(OUT, CIPHER, BLOCK_LENGTH * 2) != 0){
        error_exit("AES_CBC_Cipher IS NOT CORRECT");
    }
    
    AES_CBC_InvCipher(CIPHER, OUT, 2, w, IV);
    if (memcmp(OUT, PLAIN, BLOCK_LENGTH * 2) != 0){
        error_exit("AES_CBC_InvCipher IS NOT CORRECT");
    }
    printf("AES-CBC-128 is correct\n");

    return EXIT_SUCCESS;
}