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

  BIGNUM *n, *e, *d, *m, *c;
  n = BN_new(); e = BN_new();
  d = BN_new(); m = BN_new(); c = BN_new(); 
 

  // Set the public key exponent e
  BN_hex2bn(&e, "010001");
  // Set the public key n
  BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  //Set private key d
  BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

  // Signature: calculate m^d mod n
  BN_hex2bn(&m, "49206f776520796f752024333030302e");    
  BN_mod_exp(c, m, d, n, ctx);
  printBN("Signature:", c);


  // Clear the sensitive data from the memory             
  BN_clear_free(d); 
  BN_clear_free(m); BN_clear_free(c);

  return 0;
}

