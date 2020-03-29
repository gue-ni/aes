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
#include "test.h"

#define AES_CBC (0xcbc)
#define AES_ECB (0xecb)

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
    for (int k = 0; k < BLOCK_LENGTH; k++) printf("%02x", out[k]);
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
    for (int k = 0; k < BLOCK_LENGTH; k++) printf("%02x", out[k]);
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

void AES_CBC_InvCipher(uint8_t *in, uint8_t *out, const int n, const uint8_t *w, const uint8_t *iv){
    uint8_t prev[BLOCK_LENGTH];
    uint8_t temp[BLOCK_LENGTH];

    memcpy(prev, iv, BLOCK_LENGTH);

    for (int i = 0; i < n; i++){
        AES_InvCipher(in+(i * BLOCK_LENGTH), temp, w);
        XOR_block(temp, prev, out+(i * BLOCK_LENGTH));
        memcpy(prev, in+(i * BLOCK_LENGTH), BLOCK_LENGTH);
   }
}

int main(int argc, char **argv){
    Nk = 4;
    Nr = 10;
    printf("AES-%d (Nk=%d, Nr=%d)\n", Nk*32, Nk, Nr);
    uint8_t w[BLOCK_LENGTH * (Nr + 1)];
    uint8_t OUT[64];
    uint8_t key[Nk*4], iv[Nb*4], plain[64], cipher[64];

    char *key_arg = NULL, *iv_arg = NULL;
    int mode = AES_ECB;
    int decrypt = 0;
    int key_len = 16; 

    int c;
    while( (c = getopt(argc, argv, "i:k:m:de")) != -1 ){
		switch( c ){
			case 'i':
                iv_arg = optarg;
                read_hex(iv_arg, iv, BLOCK_LENGTH);
                break;
			case 'k':
                key_arg = optarg;
                key_len = strlen(key_arg) / 2;
                printf("Key length: %d\n", key_len);
                read_hex(optarg, key, key_len);
                break;
            case 'm':
                if (memcmp(optarg, "aes-128-cbc", 11) == 0){
                    mode = AES_CBC;
                    printf("CBC Mode\n");
                    break;
                }
                if (memcmp(optarg, "aes-128-ecb", 11) == 0){
                    mode = AES_ECB;
                    printf("ECB Mode\n");
                    break;
                }
                error_exit("Invalid mode");
                break;
            case 'd':
                decrypt = 1;
                break;
            case 'e':
                break;
			default:
				exit(EXIT_FAILURE);
				break;
		}
	}

    if(key_arg == NULL) error_exit("Key is not set");
    if(iv_arg == NULL && AES_CBC == mode) error_exit("IV is not set");

    for (int k = 0; k < BLOCK_LENGTH; k++) printf("%02x", key[k]);
    printf("\n");

    read_hex("00112233445566778899aabbccddeeff", plain, 16);
    read_hex("69c4e0d86a7b0430d8cdb78070b4c55a", cipher, 16);

    if (mode == AES_ECB){
        if (decrypt){
            AES_InvCipher(plain, OUT, w);

        } else {
            AES_Cipher(plain, OUT, w);
        }
    }


    printf("\n[TEST] AES-128-ECB (NIST FIPS)\n");
    KeyExpansion(key, w);
    AES_Cipher(plain, OUT, w);
    if (memcmp(OUT, cipher, BLOCK_LENGTH) != 0) printf("\ncipher not correct");
    memset(OUT, 0, BLOCK_LENGTH);
    printf("\n");
    AES_InvCipher(cipher, OUT, w);
    if (memcmp(OUT, plain, BLOCK_LENGTH) != 0) printf("\ninvcipher not correct");
    printf("\n=====================================\n");





/*
    printf("\n[TEST] AES-128-ECB (NIST FIPS)\n");
    read_hex("000102030405060708090a0b0c0d0e0f", key, 16);
    read_hex("00112233445566778899aabbccddeeff", plain, 16);
    read_hex("69c4e0d86a7b0430d8cdb78070b4c55a", cipher, 16);
    KeyExpansion(key, w);
    AES_Cipher(plain, OUT, w);
    if (memcmp(OUT, cipher, BLOCK_LENGTH) != 0) printf("\ncipher not correct");
    memset(OUT, 0, BLOCK_LENGTH);
    printf("\n");
    AES_InvCipher(cipher, OUT, w);
    if (memcmp(OUT, plain, BLOCK_LENGTH) != 0) printf("\ninvcipher not correct");
    printf("\n=====================================\n");

    printf("\n[TEST] AES-128-ECB\n");
    read_hex("2B7E151628AED2A6ABF7158809CF4F3C", key, 16);
    read_hex("6BC1BEE22E409F96E93D7E117393172A", plain, 16);
    read_hex("3AD77BB40D7A3660A89ECAF32466EF97", cipher, 16);
    KeyExpansion(key, w);
    AES_Cipher(plain, OUT, w);
    if (memcmp(OUT, cipher, BLOCK_LENGTH) != 0) printf("\ncipher not correct");
    memset(OUT, 0, BLOCK_LENGTH);
    printf("\n");
    AES_InvCipher(cipher, OUT, w);
    if (memcmp(OUT, plain, BLOCK_LENGTH) != 0) printf("\ninvcipher not correct");
    printf("\n=====================================\n");

    printf("\n[TEST] AES-128-ECB\n");
    read_hex("2B7E151628AED2A6ABF7158809CF4F3C", key, 16);
    read_hex("F69F2445DF4F9B17AD2B417BE66C3710", plain, 16);
    read_hex("7B0C785E27E8AD3F8223207104725DD4", cipher, 16);
    KeyExpansion(key, w);
    AES_Cipher(plain, OUT, w);
    if (memcmp(OUT, cipher, BLOCK_LENGTH) != 0) printf("\ncipher not correct");
    memset(OUT, 0, BLOCK_LENGTH);
    printf("\n");
    AES_InvCipher(cipher, OUT, w);
    if (memcmp(OUT, plain, BLOCK_LENGTH) != 0) printf("\ninvcipher not correct");
    printf("\n=====================================\n");

    printf("\n[TEST] AES-128-CBC\n");
    read_hex("2B7E151628AED2A6ABF7158809CF4F3C", key, 16);
    read_hex("000102030405060708090A0B0C0D0E0F", iv, 16);
    read_hex("6BC1BEE22E409F96E93D7E117393172A", plain, 16);
    read_hex("7649ABAC8119B246CEE98E9B12E9197D", cipher, 16);
    KeyExpansion(key, w);
    AES_CBC_Cipher(plain, OUT, 1, w, iv);
    if (memcmp(OUT, cipher, BLOCK_LENGTH) != 0) printf("\ncipher not correct");
    memset(OUT, 0, BLOCK_LENGTH);
    printf("\n");
    AES_CBC_InvCipher(cipher, OUT, 1, w, iv);
    if (memcmp(OUT, plain, BLOCK_LENGTH) != 0) printf("\ninvcipher not correct");
    printf("\n=====================================\n");

    printf("\n[TEST] AES-128-CBC\n");
    read_hex("56e47a38c5598974bc46903dba290349", key, 16);
    read_hex("8ce82eefbea0da3c44699ed7db51b7d9", iv, 16);
    read_hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf", plain, 64);
    read_hex("c30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da55", cipher, 64);
    KeyExpansion(key, w);
    AES_CBC_Cipher(plain, OUT, 4, w, iv);
    if (memcmp(OUT, cipher, 64) != 0) printf("\ncipher not correct");
    memset(OUT, 0, 64);
    printf("\n");
    AES_CBC_InvCipher(cipher, OUT, 4, w, iv);
    if (memcmp(OUT, plain, 64) != 0) printf("\ninvcipher not correct");
    printf("\n=====================================\n");
    */
    return EXIT_SUCCESS;
}