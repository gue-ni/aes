#!/bin/bash
# IV and KEY files are ascii hex representation, plain and cipher are binary

#cat data/plain_aes_128_ecb_001 | ./aes -e -k $(cat data/key_aes_128_ecb_001) -m ecb > data/tmp
#diff data/tmp data/cipher_aes_128_ecb_001 && echo success
#rm data/tmp

#cat data/cipher_aes_128_ecb_001 | ./aes -d -k $(cat data/key_aes_128_ecb_001) -m ecb > data/tmp
#diff data/tmp data/plain_aes_128_ecb_001 && echo success
#rm data/tmp

#cat data/plain_aes_128_cbc_001 | ./aes -e \
#-k $(cat data/key_aes_128_cbc_001) -i $(cat data/iv_aes_128_cbc_001) -m cbc > data/tmp
#diff data/tmp data/cipher_aes_128_cbc_001 && echo success
#rm data/tmp

#cat data/cipher_aes_128_cbc_001 | ./aes -d \
#-k $(cat data/key_aes_128_cbc_001) -i $(cat data/iv_aes_128_cbc_001) -m cbc > data/tmp
#diff data/tmp data/plain_aes_128_cbc_001 && echo success
#rm data/tmp

#cat data/plain_aes_128_cbc_002 | ./aes -e \
#-k $(cat data/key_aes_128_cbc_002) -i $(cat data/iv_aes_128_cbc_002) -m cbc > data/tmp
#diff data/tmp data/cipher_aes_128_cbc_002 && echo success
#rm data/tmp

#cat data/cipher_aes_128_cbc_002 | ./aes -d \
#-k $(cat data/key_aes_128_cbc_002) -i $(cat data/iv_aes_128_cbc_002) -m cbc > data/tmp
#diff data/tmp data/plain_aes_128_cbc_002 && echo success
#rm data/tmp

cat data/plain3 | ./aes -e \
-k $(cat data/key_aes_128_cbc_002) -i $(cat data/iv_aes_128_cbc_002) -m cbc > data/tmp
cat data/tmp | ./aes -d \
-k $(cat data/key_aes_128_cbc_002) -i $(cat data/iv_aes_128_cbc_002) -m cbc > data/tmp
diff data/tmp data/plain3 && echo success
rm data/tmp

#cat data/plain | ./aes -e \
#-k $(cat data/key_aes_128_ecb_001) -m ecb > data/tmp
#cat data/tmp | ./aes -d \
#-k $(cat data/key_aes_128_ecb_001) -m ecb > data/tmp
#diff data/tmp data/plain && echo success
#rm data/tmp

echo -n "Hello World!" > data/input
cat data/input| ./aes -e \
-k $(cat data/key_aes_128_cbc_001) -i $(cat data/iv_aes_128_cbc_002) -m cbc > data/tmp
cat data/tmp | ./aes -d \
-k $(cat data/key_aes_128_cbc_001) -i $(cat data/iv_aes_128_cbc_002) -m cbc > data/tmp
diff data/tmp data/input && echo success

cat data/image.png | ./aes -e \
-k $(cat data/key_aes_128_cbc_002) -i $(cat data/iv_aes_128_cbc_002) -m cbc > data/tmp
cat data/tmp | ./aes -d \
-k $(cat data/key_aes_128_cbc_002) -i $(cat data/iv_aes_128_cbc_002) -m cbc > data/tmp
mv data/tmp data/test.png
diff data/test.png data/image.png && echo success






