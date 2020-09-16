/**
 * @file aes-cbc.h
 * @author Jakob G. Maier <e11809618@student.tuwien.ac.at>
 * @date 31.03.2020
 */
#include <unistd.h>
#include <stdint.h>
#include "common.h"

#define MODE "cbc"
#define KEY_LEN (128)

int main(int argc, char **argv){
    char *direction = "-e";
    char *iv    = "000102030405060708090a0b0c0d0e0f";
    char *key   = "2B7E151628AED2A6ABF7158809CF4F3C";

    uint8_t dir = 1;
    int c;

    while( (c = getopt(argc, argv, "dek:i:")) != -1 ){
		switch( c ){
			case 'd':
                dir = 0;
                direction = "-d";
                break;
			case 'e':
                break;
            /*
            case 'k':
                key = optarg;
                break;
            case 'i':
                iv = optarg;
                break;
            */
            default:
                break;
        }
    }

    int pipefd[2];
    pipe(pipefd);

    int p;
    if ((p = fork())){  
        close(pipefd[dir]);
        dup2(pipefd[!dir], dir == 1 ? STDIN_FILENO : STDOUT_FILENO);
        close(pipefd[!dir]);
        execlp("./aes", "./aes", direction, "-k", key, "-i", iv, "-l", KEY_LEN, "-m", MODE, NULL);

    } else { 
        close(pipefd[!dir]);
        dup2(pipefd[dir], dir == 1 ? STDOUT_FILENO : STDIN_FILENO);
        close(pipefd[dir]);
        execlp("./pkcs7", "./pkcs7", direction, NULL);
    }
    return 0;
}