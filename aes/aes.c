/**
 * @file aes.c
 * @author Jakob G. Maier <e11809618@student.tuwien.ac.at>
 * @date 10.01.2020
 * 
 * @brief A small implementation of the Advanced Encryption Standard 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include "common.h"

uint8_t PLAINTEXT[16]   = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; 
uint8_t KEY_128_1[16]   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
uint8_t KEY_128_2[16]   = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t KEY_256_1[32]   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
uint8_t KEY_256_2[32]   = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09 ,0x14, 0xdf, 0xf4 };

uint8_t OUTPUT[16];

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
            
            if (DEBUG) printf("i: %02d %02X000000\n", i, Rcon[i/Nk]);
            temp[0] = temp[0] ^ Rcon[i/Nk];
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

void InvShiftRows(){}   // TODO
void InvSubBytes(){}    // TODO
void InvMixColumns(){}  // TODO

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
    AddRoundKey(state, w+(round*BLOCK_LENGTH));

    for (round = 1; round < Nr; round++){
        _print_s(round, "start", state);
        SubBytes(state);
        _print_s(round, "s_box", state);
        ShiftRows(state);
        _print_s(round, "s_row", state);
        MixColumns(state);
        _print_s(round, "m_col", state);
        _print(round, "k_sch", w+round*BLOCK_LENGTH);
        AddRoundKey(state, w+round*BLOCK_LENGTH);

    }

    SubBytes(state);
    _print_s(round, "s_box", state);
    ShiftRows(state);
    _print_s(round, "s_row", state);
    _print(round, "k_sch", w+round*BLOCK_LENGTH);
    AddRoundKey(state, w+round*BLOCK_LENGTH);

    k = 0;
    for (i = 0; i < 4; i++){
        for (j = 0; j < Nb; j++){
            out[k++] = state[i][j];
        }
    }
    _print(round, "output", out);
}

int main(void){
    uint8_t w[BLOCK_LENGTH * (Nr + 1)];
    if (DEBUG) printf("AES-%d (Nk=%d, Nr=%d)\n", Nk*32, Nk, Nr);
    KeyExpansion(KEY_256_1, w);
    Cipher(PLAINTEXT, OUTPUT, w);
    
    if (!DEBUG) write(STDOUT_FILENO, OUTPUT, BLOCK_LENGTH);
    return 0;
}