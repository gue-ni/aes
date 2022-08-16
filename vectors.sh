#!/bin/bash

cat data/plain_aes_128_ecb_001 | ./aes -e -k $(cat data/key_aes_128_ecb_001) -m ecb -l 128 > data/tmp
diff data/tmp data/cipher_aes_128_ecb_001 && echo success
rm data/tmp

cat data/cipher_aes_128_ecb_001 | ./aes -d -k $(cat data/key_aes_128_ecb_001) -m ecb > data/tmp
diff data/tmp data/plain_aes_128_ecb_001 && echo success
rm data/tmp

cat data/plain_aes_128_cbc_001 | ./aes -e \
-k $(cat data/key_aes_128_cbc_001) -i $(cat data/iv_aes_128_cbc_001) -m cbc > data/tmp
diff data/tmp data/cipher_aes_128_cbc_001 && echo success
rm data/tmp

cat data/cipher_aes_128_cbc_001 | ./aes -d \
-k $(cat data/key_aes_128_cbc_001) -i $(cat data/iv_aes_128_cbc_001) -m cbc > data/tmp
diff data/tmp data/plain_aes_128_cbc_001 && echo success
rm data/tmp

cat data/plain_aes_128_cbc_002 | ./aes -e \
-k $(cat data/key_aes_128_cbc_002) -i $(cat data/iv_aes_128_cbc_002) -m cbc > data/tmp
diff data/tmp data/cipher_aes_128_cbc_002 && echo success
rm data/tmp

cat data/cipher_aes_128_cbc_002 | ./aes -d \
-k $(cat data/key_aes_128_cbc_002) -i $(cat data/iv_aes_128_cbc_002) -m cbc > data/tmp
diff data/tmp data/plain_aes_128_cbc_002 && echo success
rm data/tmp

