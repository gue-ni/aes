# Advanced Encryption Standard

## Usage
Key:
2B7E151628AED2A6ABF7158809CF4F3C

IV:
000102030405060708090a0b0c0d0e0f

### Encrypt
cat plain.txt | ./pkcs7 -e | ./aes -e -k [key] -i [iv] -m cbc > encrypted.txt
  
### Decrypt
cat encrypted.txt | ./aes -d -k [key] -i [iv] -m cbc | ./pkcs7 -d > plain.txt

