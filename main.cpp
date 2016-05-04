/**
 * 
 * Simple RSA implementation
 * by Jakub Vojvoda [vojvoda@swdeveloper.sk]
 * 2016
 * 
 **/

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <ctime>
#include <gmp.h>

// RSA parameters where (e, n) is public key
// and (d, n) is private key
typedef struct rsa {
  
  mpz_t p, q;  // prime numbers
  mpz_t n;     // public modulus
  mpz_t e, d;  // public and private exponent
  
  rsa() {
    mpz_init(p);
    mpz_init(q);
    mpz_init(n);
    mpz_init(e);
    mpz_init(d);
  }
  
  ~rsa() {
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(d);
  }
  
} rsa_t;

void alert(char *name, std::string msg);
rsa_t keygen(long int lenb);
void crypt(mpz_t key, mpz_t n, mpz_t msg, mpz_t &out);
void primegen(gmp_randstate_t randstate, mpz_t &key, mpz_t min, mpz_t max);
void range(long int bitsize, mpz_t &min, mpz_t &max);
void gcd(mpz_t &g, mpz_t &s, mpz_t &t, mpz_t a, mpz_t b);
void nextprime(gmp_randstate_t randstate, mpz_t &key, mpz_t value);
bool isprime(gmp_randstate_t randstate, mpz_t value, unsigned int iter);
void invert(mpz_t &rinv, mpz_t a, mpz_t b);


int main (int argc, char **argv)
{ 
  // RSA key generating 
  if (argc == 3 && std::strcmp(argv[1], "-g") == 0) {
    
    mpz_t b;
    mpz_init(b);
    
    if (mpz_set_str(b, argv[2], 0) != 0) {
     alert(argv[0], "not valid number format");
     return 1;
    }
    
    // length of public modulus in bits
    long int lenb = mpz_get_si(b);

    if (lenb < 0) {
      alert(argv[0], "negative size of modulus");
      return 1;
    }    
    
    // key generating
    rsa_t par = keygen(lenb);
    
    gmp_printf("%#Zx %#Zx %#Zx %#Zx %#Zx\n", par.p, par.q, par.n, par.e, par.d);
    
    mpz_clear(b);
  }
  // Encryption and decryption of message/ciphertext
  else if (argc == 5 && (std::strcmp(argv[1], "-e") == 0 || std::strcmp(argv[1], "-d") == 0)) {
    
    mpz_t key, n, mc;
    mpz_init(key);
    mpz_init(n);
    mpz_init(mc);

    if (mpz_set_str(key, argv[2], 0) != 0 ||
        mpz_set_str(n, argv[3], 0) != 0 || 
        mpz_set_str(mc, argv[4], 0) != 0) {
      
      alert(argv[0], "not valid number format");
      return 1;
    }
    
    mpz_t out;
    
    // encrypting/decrypting
    crypt(key, n, mc, out);

    gmp_printf("%#Zx\n", out);
    
    mpz_clear(key);
    mpz_clear(n);
    mpz_clear(mc);
    mpz_clear(out);
  }
  // Unknown option
  else {
    alert(argv[0], "unknown option or argument format");
    return 1;
  }
  
  return 0;
}


void alert(char *name, std::string msg)
{
  std::cerr << name << ": " << msg << std::endl; 
}

// Encrypt/decrypt message/ciphertext by computing 
// out = msg^key mod n
void crypt(mpz_t key, mpz_t n, mpz_t msg, mpz_t &out)
{
  mpz_init(out);
  mpz_powm(out, msg, key, n);
}

// Generate prime number in range min..max
void primegen(gmp_randstate_t randstate, mpz_t &key, mpz_t min, mpz_t max)
{
  mpz_init(key);
  
  mpz_t rndmax, rndval;
  mpz_init(rndmax);
  mpz_init(rndval);
  mpz_sub_ui(min, min, 1);
  mpz_sub(rndmax, max, min);
	
  // find random number in range
  mpz_urandomm(rndval, randstate, rndmax);
  mpz_add(rndval, rndval, min);
  mpz_add_ui(rndval, rndval, 1);

  // calculate next prime number
  nextprime(randstate, key, rndval);

  mpz_clear(rndmax);
  mpz_clear(rndval); 
}

// Compute possible value range of two numbers with n-bit product
void range(long int bitsize, mpz_t &min, mpz_t &max)
{
  mpz_init(min);
  mpz_init(max);

  mpz_t tmin, tmax, base;
  mpz_init(tmin);
  mpz_init(tmax);  
  mpz_init(base);
  mpz_set_ui(base, 2);

  // compute minimal value of product
  mpz_pow_ui(tmin, base, bitsize - 1);

  // compute maximal value of product
  mpz_pow_ui(tmax, base, bitsize);
  mpz_sub_ui(tmax, tmax, 1);

  mpz_t rem;
  mpz_init(rem);
  
  // compute minimal value of numbers
  mpz_sqrtrem(min, rem, tmin);

  if (mpz_cmp_ui(rem, 0) != 0) {
    mpz_add_ui(min, min, 1);
  }

  // compute maximal value of numbers
  mpz_sqrt(max, tmax);
  
  mpz_clear(tmin);
  mpz_clear(tmax);
  mpz_clear(base);
  mpz_clear(rem);
}

// Generate key with n-bit public modulus
rsa_t keygen(long int lenb)
{ 
  rsa_t par;    
  
  if (lenb < 3) {
    return par;
  }

  gmp_randstate_t randstate; 
  gmp_randinit_default(randstate);
  
  // compute generator seed
  unsigned long int seed = time(NULL);
  std::ifstream randfile("/dev/urandom");
    
  if (randfile.is_open()) {    
    randfile.read((char *)&seed, sizeof(seed));
    randfile.close();
  }
  
  // initilize random generator
  gmp_randseed_ui(randstate, seed);

  // compute range and prime numbers p and q
  mpz_t vmin, vmax;
  range(lenb, vmin, vmax);
  primegen(randstate, par.p, vmin, vmax);
  primegen(randstate, par.q, vmin, vmax);
 
  // compute public modulus n
  mpz_mul(par.n, par.p, par.q);

  // compute phi
  mpz_t p1, q1, phi;
  mpz_init(p1);
  mpz_init(q1);
  mpz_init(phi);
  mpz_sub_ui(p1, par.p, 1);
  mpz_sub_ui(q1, par.q, 1);
  mpz_mul(phi, p1, q1);

  mpz_t rand, rgcd, s, t;
  mpz_init(rand);
  mpz_init(rgcd);
  mpz_init(s);
  mpz_init(t);

  mpz_set_ui(par.e, 3);    
  gcd(rgcd, s, t, par.e, phi);      

  // compare result of gcd with 1
  while (mpz_cmp_ui(rgcd, 1) != 0) {
    
    // choose random e in range 1..phi
    mpz_urandomm(rand, randstate, phi);
    mpz_add_ui(par.e, rand, 1);
    
    // compute the greatest common divisor 
    gcd(rgcd, s, t, par.e, phi);      
  }
	
  // compute multiplicative inverse
  invert(par.d, par.e, phi);    

  gmp_randclear(randstate);
  mpz_clear(vmin);
  mpz_clear(vmax);
  mpz_clear(p1);
  mpz_clear(q1);
  mpz_clear(phi);
  mpz_clear(rand);
  mpz_clear(rgcd);
  mpz_clear(s);
  mpz_clear(t);
  
  return par;
}

// Implementation of the Extended Euclidean algorithm
// for computing greatest common divisor and inversion
void gcd(mpz_t &g, mpz_t &s, mpz_t &t, mpz_t a, mpz_t b) 
{
  mpz_t r0, r1;
  mpz_init(r0);
  mpz_init(r1);
  mpz_set(r0, b);
  mpz_set(r1, a);

  mpz_t s0, s1;
  mpz_init(s0);
  mpz_init(s1);
  mpz_set_si(s0, 0);
  mpz_set_si(s1, 1);

  mpz_t t0, t1;
  mpz_init(t0);
  mpz_init(t1);
  mpz_set_si(t0, 1);
  mpz_set_si(t1, 0);
  
  mpz_t q;
  mpz_init(q);
  
  while (mpz_cmp_si(r0, 0) != 0) {    
    mpz_div(q, r1, r0);
    
    mpz_t rtmp, stmp, ttmp;
    mpz_init(rtmp);
    mpz_init(stmp);
    mpz_init(ttmp);
    
    mpz_mul(rtmp, q, r0);
    mpz_mul(stmp, q, s0);
    mpz_mul(ttmp, q, t0);
    
    mpz_swap(r0, r1);  
    mpz_sub(r0, r0, rtmp);
    
    mpz_swap(s0, s1);  
    mpz_sub(s0, s0, stmp);

    mpz_swap(t0, t1);  
    mpz_sub(t0, t0, ttmp);

    mpz_clear(rtmp);       
    mpz_clear(stmp);        
    mpz_clear(ttmp);         
  }
  
  mpz_init(g);  
  mpz_abs(r1, r1);
  mpz_set(g, r1);
  
  mpz_init(s);    
  mpz_set(s, s1);

  mpz_init(t);   
  mpz_set(t, t1);
  
  mpz_clear(r0);
  mpz_clear(r1);
  mpz_clear(s0);
  mpz_clear(s1);
  mpz_clear(t0);
  mpz_clear(t1);  
  mpz_clear(q);
}

// Find next prime number greater than value 
void nextprime(gmp_randstate_t randstate, mpz_t &key, mpz_t value) 
{
  mpz_init(key);
  mpz_set(key, value);
  
  // check if number is already prime
  while (!isprime(randstate, key, 25)) {
    mpz_add_ui(key, key, 1);
  }
}

// Implementation of prime number test where firstly the trial divisions 
// are performed and then the Miller-Rabin algorithm is used
bool isprime(gmp_randstate_t randstate, mpz_t value, unsigned int iter)
{
  if (mpz_cmp_ui(value, 1) == 0) {
    return false;
  }

  // prepare vector of first few prime numbers
  static const unsigned int els[] = {2,3,5,7,11,13,17,19,23,29,31,37,41,43,47};
  std::vector<unsigned int> ts(els, els + sizeof(els) / sizeof(els[0]));

  for (unsigned int i = 0; i < ts.size(); i++) {

    // check if number is equal to prime number
    if (mpz_cmp_ui(value, ts.at(i)) == 0) {
      return true;
    }    
    
    // check if number is divisible by prime number
    if (mpz_divisible_ui_p(value, ts.at(i)) > 0) {
      return false;
    }
  }
  
  mpz_t n, d, r;
  mpz_init(n);
  mpz_init(d);
  mpz_init(r);

  // write n-1 as 2^r.d
  mpz_sub_ui(n, value, 1);
  mpz_sub_ui(d, value, 1);
  
  while (mpz_even_p(d) > 0) {
    mpz_tdiv_q_2exp(d, d, 1);
    mpz_add_ui(r, r, 1);
  }
  
  bool bcont;

  for (unsigned int i = 0; i < iter; i++) {

    bcont = false;    
    
    // pick random number in range 2..n-2
    mpz_t a, rndrange;
    mpz_init(a);
    mpz_init(rndrange);

    mpz_sub_ui(rndrange, n, 2);
    mpz_urandomm(a, randstate, rndrange);
    mpz_add_ui(a, a, 2);

    // compute x = a^d mod n    
    mpz_t x;
    mpz_init(x);
    mpz_powm(x, a, d, value);
    
    if (mpz_cmp_ui(x, 1) == 0 || mpz_cmp(x, n) == 0) {
      continue;
    }
    
    for (unsigned int j = 1; mpz_cmp_ui(r, j) > 0; j++) {    
      
      // compute x = x^2 mod n
      mpz_mul(x, x, x);
      mpz_mod(x, x, value);
      
      if (mpz_cmp_ui(x, 1) == 0) {
        mpz_clear(n);
        mpz_clear(d);
        mpz_clear(r);
        mpz_clear(a);
        mpz_clear(x);
        mpz_clear(rndrange);
        return false;
      }
      
      if (mpz_cmp(x, n) == 0) {
        bcont = true;        
        break;
      }          
    }
  
    if (!bcont) {
	  mpz_clear(n);
      mpz_clear(d);
      mpz_clear(r);
      mpz_clear(a);
      mpz_clear(x);
      mpz_clear(rndrange);
      return false;
    }
    
    mpz_clear(a);
	mpz_clear(x);
	mpz_clear(rndrange);
  }
  
  mpz_clear(n);
  mpz_clear(d);
  mpz_clear(r);
  return true;
}

// Implementation of multiplicative inverse 
// using the Extended Euclidean algorithm
void invert(mpz_t &rinv, mpz_t a, mpz_t b)
{
  mpz_t g, s, t;
  mpz_init(g);
  mpz_init(s);
  mpz_init(t);
  
  // compute coeficients
  gcd(g, s, t, a, b);
  
  if (mpz_cmp_si(s, 0) < 0) {
    mpz_add(s, s, b);
  }   

  mpz_init(rinv);
  mpz_set(rinv, s);
  
  mpz_clear(g);
  mpz_clear(s);
  mpz_clear(t);
}

