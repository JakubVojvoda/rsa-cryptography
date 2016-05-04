# rsa-implementation
Simple RSA key generation, text encryption and ciphertext decryption

## usage
**key generation :** ./rsa -g B<br />
**text encryption :** ./rsa -e E N M<br />
**ciphertext decryption :** ./rsa -d D N C<br />

B ... size of public modulus in bits<br />
P ... randomly generated prime number<br />
Q ... randomly generated prime number<br />
N ... public modulus<br />
E ... public exponent<br />
D ... private exponent<br />
M ... plaintext message (number, not text)<br />
C ... ciphertext message (number, not text)<br />
