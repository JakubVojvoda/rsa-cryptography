# rsa-implementation
Simple RSA key generation, text encryption and ciphertext decryption

## usage

<dl>
  <dt>key generation:</dt>
  <dd>input: ./rsa -g B<br />output: P Q N E D</dd>
<dl>
  <dt>text encryption:</dt>
  <dd>input: ./rsa -e E N M<br />output: C</dd>
<dl>
  <dt>ciphertext decryption:</dt>
  <dd>input: ./rsa -d D N C<br />output: M</dd>

B ... size of public modulus in bits<br />
P ... randomly generated prime number<br />
Q ... randomly generated prime number<br />
N ... public modulus<br />
E ... public exponent<br />
D ... private exponent<br />
M ... plaintext message (number, not text)<br />
C ... ciphertext message (number, not text)<br />
