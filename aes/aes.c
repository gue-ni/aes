/**
 * @file aes.c
 * @author Jakob G. Maier <e11809618@student.tuwien.ac.at>
 * @date 31.03.2020
 * 
 * @brief A small implementation of the Advanced Encryption Standard 
 * 
 * TODO: 
 * dup2
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

#define AES_CBC (0xcbc)
#define AES_ECB (0xecb)
#define ENCRYPT (1)
#define DECRYPT (!ENCRYPT)

int Nk, Nr;

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

void InvCipher(const uint8_t *in, uint8_t *out, const uint8_t *w){
    uint8_t state[4][Nb];
    int i, j, k = 0, rp = 1;

    for (i = 0; i < 4; i++){
        for (j = 0; j < Nb; j++){
            state[i][j] = in[k++];
        }
    }
    #ifdef DEBUG
    _print_s(rp, "iinput", state);
    _print_r(rp, "ik_sch", w+(Nr*BLOCK_LENGTH));
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
        _print_r(rp, "ik_sch", w+round*BLOCK_LENGTH);
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
    _print_r(rp, "ik_sch", w);
    #endif
    AddRoundKey(state, w);

    k = 0;
    for (i = 0; i < 4; i++){
        for (j = 0; j < Nb; j++){
            out[k++] = state[i][j];
        }
    }
    #ifdef DEBUG
    _print_r(rp, "ioutput", out);
    #endif
}

void Cipher(const uint8_t *in, uint8_t *out, const uint8_t *w){
    uint8_t state[4][Nb];
    int round = 0;
    #ifdef DEBUG
    _print_r(round, "input", in);
    #endif
    
    int i, j, k = 0;
    for (i = 0; i < 4; i++){
        for (j = 0; j < Nb; j++){
            state[i][j] = in[k++];
        }
    }
    
    #ifdef DEBUG
    _print_r(round, "k_sch", w);
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
        _print_r(round, "k_sch", w+round*BLOCK_LENGTH);
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
    _print_r(round, "k_sch", w+round*BLOCK_LENGTH);
    #endif
    AddRoundKey(state, w+round*BLOCK_LENGTH);

    k = 0;
    for (i = 0; i < 4; i++){
        for (j = 0; j < Nb; j++){
            out[k++] = state[i][j];
        }
    }

    #ifdef DEBUG
    _print_r(round, "output", out);
    #endif
}

void XOR(uint8_t *a, uint8_t *b, uint8_t *out){
    for (int i = 0; i < BLOCK_LENGTH; i++){
        out[i] = a[i] ^ b[i];
    }
}

void AES_CBC_Cipher(const uint8_t *w, const uint8_t *iv, uint8_t encrypt){
    uint8_t prev[BLOCK_LENGTH], temp[BLOCK_LENGTH], buf[BLOCK_LENGTH], out[BLOCK_LENGTH];
    
    memcpy(prev, iv, BLOCK_LENGTH);

    while(fread(buf, 1, BLOCK_LENGTH, stdin)){
        if (encrypt){
            XOR(buf, prev, temp);
            Cipher(temp, out, w);
            memcpy(prev, out, BLOCK_LENGTH);
            fwrite(out, 1, BLOCK_LENGTH, stdout);
        }else{
            InvCipher(buf, temp, w);
            XOR(temp, prev, out);
            memcpy(prev, buf, BLOCK_LENGTH);
            fwrite(out, 1, BLOCK_LENGTH, stdout);
        }
        memset(buf, 0x0, BLOCK_LENGTH);
    }
    
}

void AES_ECB_Cipher(const uint8_t *w, const uint8_t encrypt){
    uint8_t buf[BLOCK_LENGTH], n; 
    while((n = fread(buf, 1, BLOCK_LENGTH, stdin))){
        if (encrypt){
            Cipher(buf, buf, w);
        } else {
            InvCipher(buf, buf, w);
        }
        fwrite(buf, 1, BLOCK_LENGTH, stdout);
    }
}

int main(int argc, char **argv){
    uint8_t KEY[32], IV[BLOCK_LENGTH];
    memset(KEY, 0, 32);

    int mode = AES_ECB, direction = ENCRYPT, KEY_LEN = 0, set_iv = 0; 

    int c;
    while( (c = getopt(argc, argv, "i:k:m:de")) != -1 ){
		switch( c ){
			case 'i':
                read_hex(optarg, IV, BLOCK_LENGTH);
                set_iv = 1;
                break;
			case 'k':
                KEY_LEN = strlen(optarg) / 2;
                read_hex(optarg, KEY, KEY_LEN);
                break;
            case 'm':
                if (memcmp(optarg, "cbc", 3) == 0){
                    mode = AES_CBC;
                    break;
                }
                if (memcmp(optarg, "ecb", 3) == 0){
                    mode = AES_ECB;
                    break;
                }
                error_exit("Invalid mode");
                break;
            case 'd': direction = DECRYPT; break;
            case 'e': direction = ENCRYPT; break;
			default: exit(EXIT_FAILURE);   break;
		}
	}

    if(KEY_LEN == 0) error_exit("Key not set"); 
    if(set_iv == 0 && AES_CBC == mode) error_exit("IV is not set");
    switch (KEY_LEN){
        case 16: Nk = 4; Nr = 10; break;
        case 24: Nk = 6; Nr = 12; break;
        case 32: Nk = 8; Nr = 14; break;
        default: error_exit("Only 128, 192, and 256 bit keys are allowed"); break;
    }

    uint8_t W[BLOCK_LENGTH * (Nr + 1)];
    KeyExpansion(KEY, W);

    switch(mode){
        case (AES_ECB):
            AES_ECB_Cipher(W, direction);
            break;

        case (AES_CBC):
            AES_CBC_Cipher(W, IV, direction);
            break;
    }

    return EXIT_SUCCESS;
}