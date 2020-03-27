/**
 * @file common.c
 * @author Jakob G. Maier <e11809618@student.tuwien.ac.at>
 * @date 10.01.2020
 * 
 * @brief Implements error handling and print functions
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "common.h"


void error_exit(char *msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

void _print(int round, char *step, uint8_t *data){
    printf("round[ %d].%s \t", round, step);
    for(int i = 0; i < SIZE; i++){
        printf("%02X", data[i]);
    } 
    printf("\n");
}

void _print_w(int n, uint8_t *word){
    if (!DEBUG) return;
    printf("i: %d ", n);
    for(int i = 0; i<4; i++){
        printf("%02X",word[i]);
    }
    printf("\n");
}

void _print_l(uint8_t *word, int n){
    if (!DEBUG) return;
    for(int i = 0; i<n; i++){
        if ((i) % 4 == 0) printf(" ");
        printf("%02X",word[i]);
    }
    printf("\n");
}

void _print_s(int round, char *step, uint8_t data[][Nb]){
    printf("round[ %d].%s \t", round, step);
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++){
           printf("%02X", data[i][j]);
        }
    }
    printf("\n");
}

void _print_word(int i, int n, uint8_t *w){
    if (!DEBUG) return;
    printf("i: %d ", i);
    for (int k = 0; k < 4; k++){
        printf("%02X", w[4 * n + k]);
    }
    printf("\n");

}

void _print_state(uint8_t state[][Nb], int len){
    if (!DEBUG) return;
    for (int i = 0; i < len; i++){
        for (int j = 0; j < Nb; j++){
           printf(" %02X ", state[j][i]);
        }
        printf("\n");
    }
}


