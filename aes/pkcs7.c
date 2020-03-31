/**
 * @file pkcs7.c
 * @author Jakob G. Maier <e11809618@student.tuwien.ac.at>
 * @date 31.03.2020
 * 
 * @brief A small implementation of the PKCS#7 cryptographic padding algorithm 
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "common.h"

uint8_t padding_block[BLOCK_LENGTH];


uint8_t PKCS7(uint8_t *buf, uint8_t n){
    if (n == BLOCK_LENGTH) return BLOCK_LENGTH;
    uint8_t padding = BLOCK_LENGTH - n;
    memset(buf+n, padding, padding);
    return BLOCK_LENGTH - padding;
}

uint8_t invPKCS7(uint8_t *buf){
    uint8_t padding = buf[BLOCK_LENGTH-1];
    if (padding > BLOCK_LENGTH || padding == 0x0) return BLOCK_LENGTH;

    uint8_t len = BLOCK_LENGTH - padding;

    for (int i = len; i < BLOCK_LENGTH; i++){
        if (buf[i] != padding) return BLOCK_LENGTH;
    }
    return BLOCK_LENGTH - padding;
}

int main(int argc, char **argv){
    uint8_t buf[BLOCK_LENGTH], out[BLOCK_LENGTH]; 
    uint8_t n, len = BLOCK_LENGTH, first = 1, in;

    memset(padding_block, BLOCK_LENGTH, BLOCK_LENGTH);

    int c;
    while( (c = getopt(argc, argv, "io")) != -1 ){
		switch( c ){
            case 'i':
                in = 1;
                break;
            case 'o':
                in = 0;
                break;
            default:
                in = 1;
                break;
        }
    }

    if (in){
        while ((n = fread(buf, 1, BLOCK_LENGTH, stdin))){
            len = PKCS7(buf, n);
            fwrite(buf, 1, BLOCK_LENGTH, stdout);
        }
        if(len == BLOCK_LENGTH) fwrite(padding_block, 1, BLOCK_LENGTH, stdout);
    } else {
        while((n = fread(buf, 1, BLOCK_LENGTH, stdin))){
           if (!first){
                fwrite(out, 1, BLOCK_LENGTH, stdout);
            } else {
                first = 0;
            }
            memcpy(out, buf, BLOCK_LENGTH);
        }
        len = invPKCS7(out); 
        fwrite(out, 1, len, stdout);
    }
    return 0;
}