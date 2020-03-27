/**
 * @file lite_aes.c
 * @author Jakob G. Maier <e11809618@student.tuwien.ac.at>
 * @date 10.01.2020
 * 
 * @brief A small implementation of AES-128 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <stdbool.h>

#include "common.h"

uint8_t PLAINTEXT[16]   = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; 
uint8_t KEY[16]         = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
uint8_t OUTPUT[16];

uint8_t cipher_key_128[4 * Nk] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

static const uint8_t s_box[16][16] = 
{
    { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
    { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
    { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
    { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
    { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
    { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
    { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
    { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
    { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
    { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
    { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
    { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
    { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
    { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
    { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
    { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
};

static const uint8_t Rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

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
    memset(w, 0x0, Nke);

    while (i < Nk){
        w[4 * i + 0] = key[4 * i + 0];
        w[4 * i + 1] = key[4 * i + 1];
        w[4 * i + 2] = key[4 * i + 2];
        w[4 * i + 3] = key[4 * i + 3];
        i++;
    }

    i = Nk;
   
    while(i < Nb * (Nr + 1)){
        temp[0] = w[(i - 1) * 4 + 0];
        temp[1] = w[(i - 1) * 4 + 1];
        temp[2] = w[(i - 1) * 4 + 2];
        temp[3] = w[(i - 1) * 4 + 3];
        _print_word(i, 0, temp);

        if ( i % Nk == 0){
            RotWord(temp);
            _print_word(i, 0, temp);

            SubWord(temp);
            _print_word(i, 0, temp);
            
            if (DEBUG) printf("i: %d %02X000000\n", i, Rcon[i/Nk]);
            temp[0] = temp[0] ^ Rcon[i/Nk];
            temp[1] = temp[1] ^ 0x00;
            temp[2] = temp[2] ^ 0x00;
            temp[3] = temp[3] ^ 0x00;
            _print_word(i, 0, temp);

        } else if(Nk > 6 && i % Nk == 4){
            SubWord(temp);
            _print_word(i, 0, temp);
        } 

        _print_word(i, i-Nk, w);

        w[4 * i + 0] = w[4 * (i-Nk) + 0] ^ temp[0];
        w[4 * i + 1] = w[4 * (i-Nk) + 1] ^ temp[1];
        w[4 * i + 2] = w[4 * (i-Nk) + 2] ^ temp[2];
        w[4 * i + 3] = w[4 * (i-Nk) + 3] ^ temp[3];

        _print_word(i, i, w);

        i++;
    }
    /*
    if (DEBUG) printf("Expansion of a 128-bit Cipher key\nCipher key:\n");
    _print_l(key, 4 * Nk);
    if (DEBUG) printf("Expanded key\n");
    _print_l(w, Nke);
    */
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

uint8_t GM(uint8_t a, uint8_t b){
    if (a == 1){
        return b;
    } else if (a == 2){
        return ((b<<1) & 0xff) ^ (b & 0x80 ? 0x1b : 0x00);
    } else if (a == 3){
        return GM(2, b) ^ b;
    } else {
        return 0;
    }
}

void MixColumns(uint8_t state[4][Nb]){
    uint8_t temp[4][Nb];
    for (int i = 0; i< 4; i++){
        memcpy(temp[i], state[i], 4);
    }

    for (int c = 0; c < 4; c++){
        state[c][0] = GM(0x02, temp[c][0]) ^ GM(0x03, temp[c][1]) ^ (temp[c][2]) ^ (temp[c][3]);
        state[c][1] = (temp[c][0]) ^ GM(0x02, temp[c][1]) ^ GM(0x03, temp[c][2]) ^ (temp[c][3]);
        state[c][2] = (temp[c][0]) ^ (temp[c][1]) ^ GM(0x02, temp[c][2]) ^ GM(0x03, temp[c][3]);
        state[c][3] = GM(0x03, temp[c][0]) ^ (temp[c][1]) ^ (temp[c][2]) ^ GM(0x02, temp[c][3]);
    }
}

void AddRoundKey(uint8_t state[4][Nb], uint8_t *roundKey){
    int k = 0;
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++){
            state[i][j] = roundKey[k++] ^ state[i][j];
        }
    }
}

void InvShiftRows(){}
void InvSubBytes(){}
void InvMixColumns(){}

void Cipher(uint8_t *in, uint8_t *out, uint8_t *w){
    uint8_t state[4][Nb];
    int round = 0;
    _print(round, "input", in);
    
    int i, j, k = 0;
    for (i = 0; i < 4; i++){
        for (j = 0; j < Nb; j++){
            state[i][j] = in[k++];
        }
    }
    
    _print(round, "k_sch", w);
    AddRoundKey(state, w+round*Nrk);

    for (round = 1; round < Nr; round++){
        _print_s(round, "start", state);
        SubBytes(state);
        _print_s(round, "s_box", state);
        ShiftRows(state);
        _print_s(round, "s_row", state);
        MixColumns(state);
        _print_s(round, "m_col", state);
        _print(round, "k_sch", w+round*Nrk);
        AddRoundKey(state, w+round*Nrk);

    }

    SubBytes(state);
    _print_s(round, "s_box", state);
    ShiftRows(state);
    _print_s(round, "s_row", state);
    _print(round, "k_sch", w+round*16);
    AddRoundKey(state, w+round*Nrk);

    k = 0;
    for (i = 0; i < 4; i++){
        for (j = 0; j < Nb; j++){
            out[k++] = state[i][j];
        }
    }
    _print(round, "output", out);
}

int main(void)
{
    uint8_t w[4 * Nb * (Nr + 1)];
    printf("AES-128 (Nk=%d, Nr=%d)\n", Nk, Nr);
    KeyExpansion(KEY, w);
    Cipher(PLAINTEXT, OUTPUT, w);

/*
    uint8_t test_state[4][4] = {
        { 0xdb, 0x13, 0x53, 0x45 },
        { 0xf2, 0x0a, 0x22, 0x5c },
        { 0xdb, 0x13, 0x53, 0x45 },
        { 0xdb, 0x13, 0x53, 0x45 }
    };

    _print_state(test_state, 4);
    MixColumns(test_state);
    printf("\n");
    _print_state(test_state, 4);
*/
    return 0;
}


