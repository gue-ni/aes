#!/bin/bash
# IV and KEY files are ascii hex representation, plain and cipher are binary

cat test/plain_aes_128_ecb_001 | ./aes -e -k $(cat test/key_aes_128_ecb_001) -m ecb > test/tmp
diff test/tmp test/cipher_aes_128_ecb_001 && echo success
rm test/tmp

cat test/cipher_aes_128_ecb_001 | ./aes -d -k $(cat test/key_aes_128_ecb_001) -m ecb > test/tmp
diff test/tmp test/plain_aes_128_ecb_001 && echo success
rm test/tmp

cat test/plain_aes_128_cbc_001 | ./aes -e \
-k $(cat test/key_aes_128_cbc_001) -i $(cat test/iv_aes_128_cbc_001) -m cbc > test/tmp
diff test/tmp test/cipher_aes_128_cbc_001 && echo success
rm test/tmp

cat test/cipher_aes_128_cbc_001 | ./aes -d \
-k $(cat test/key_aes_128_cbc_001) -i $(cat test/iv_aes_128_cbc_001) -m cbc > test/tmp
diff test/tmp test/plain_aes_128_cbc_001 && echo success
rm test/tmp

cat test/plain_aes_128_cbc_002 | ./aes -e \
-k $(cat test/key_aes_128_cbc_002) -i $(cat test/iv_aes_128_cbc_002) -m cbc > test/tmp
diff test/tmp test/cipher_aes_128_cbc_002 && echo success
rm test/tmp

cat test/cipher_aes_128_cbc_002 | ./aes -d \
-k $(cat test/key_aes_128_cbc_002) -i $(cat test/iv_aes_128_cbc_002) -m cbc > test/tmp
diff test/tmp test/plain_aes_128_cbc_002 && echo success
rm test/tmp




