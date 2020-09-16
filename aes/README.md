# Advanced Encryption Standard

## Usage
### Encrypt
cat plain.txt | ./pkcs7 -e | ./aes -e -k <key> -i <iv> -m cbc > encrypted.txt
  
### Decrypt
cat encrypted.txt | ./aes -d -k [key] -i <iv> -m cbc | ./pkcs7 -d > plain.txt

