#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 512 

void printBN(char *msg, BIGNUM * a)
{
   char * number_str = BN_bn2hex(a);
   printf("%s %s\n", msg, number_str);
   OPENSSL_free(number_str);
}

int main ()
{
  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *n, *e, *s, *m;
  n = BN_new(); e = BN_new();
  s = BN_new(); m = BN_new();
 

  // Set the public key exponent e
  BN_hex2bn(&e, "010001");
  // Set the public key n
  BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
 
  // Verify sign: calculate s^e mod n to get the message
  BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");    
  BN_mod_exp(m, s, e, n, ctx);
  printBN("Original message:", m);
  

  // Clear the sensitive data from the memory             
  BN_clear_free(m); BN_clear_free(s);

  return 0;
}

