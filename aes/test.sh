#!/bin/bash
# IV and KEY files are ascii hex representation, plain and cipher are binary

cat data/plain | ./pkcs7 -i | ./aes -e \
-k $(cat data/key_aes_128_cbc_002) -i $(cat data/iv_aes_128_cbc_002) -m cbc > data/out
cat data/out |./aes -d \
-k $(cat data/key_aes_128_cbc_002) -i $(cat data/iv_aes_128_cbc_002) -m cbc | ./pkcs7 -o > data/tmp
diff data/tmp data/plain && echo success
rm data/tmp data/out

echo "Hello World!!!" > data/input
cat data/input | ./pkcs7 -i | ./aes -e \
-k $(cat data/key_aes_128_cbc_001) -i $(cat data/iv_aes_128_cbc_001) -m cbc > data/out
cat data/out | ./aes -d \
-k $(cat data/key_aes_128_cbc_001) -i $(cat data/iv_aes_128_cbc_001) -m cbc | ./pkcs7 -o > data/tmp
diff data/tmp data/input && echo success
rm data/input data/tmp data/out

echo -n "Hello World!" | ./pkcs7 -i > data/input
cat data/input | ./aes -e \
-k $(cat data/key_aes_128_cbc_001) -i $(cat data/iv_aes_128_cbc_001) -m cbc > data/out
cat data/out | ./aes -d \
-k $(cat data/key_aes_128_cbc_001) -i $(cat data/iv_aes_128_cbc_001) -m cbc > data/tmp
diff data/tmp data/input && echo success
rm data/tmp data/input data/out

cat data/image.png | ./pkcs7 -i | ./aes -e \
-k $(cat data/key_aes_128_cbc_002) -i $(cat data/iv_aes_128_cbc_002) -m cbc > data/out
cat data/out | ./aes -d \
-k $(cat data/key_aes_128_cbc_002) -i $(cat data/iv_aes_128_cbc_002) -m cbc | ./pkcs7 -o > data/tmp
diff data/tmp data/image.png && echo success
rm data/tmp data/out





