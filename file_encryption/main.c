#include "api.h"
#include "ascon.h"
#include "crypto_aead.h"
#include "permutations.h"
#include "printstate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

forceinline void ascon_loadkey(ascon_key_t* key, const uint8_t* k) {
  key->x[0] = KEYROT(0, LOADBYTES(k, 4));
  key->x[1] = LOADBYTES(k + 4, 8);
  key->x[2] = LOADBYTES(k + 12, 8);
}

forceinline void ascon_initaead(ascon_state_t* s, const ascon_key_t* key,
                                const uint8_t* npub) {
  s->x[0] = key->x[0] ^ ASCON_80PQ_IV;
  s->x[1] = key->x[1];
  s->x[2] = key->x[2];
  s->x[3] = LOAD(npub, 8);
  s->x[4] = LOAD(npub + 8, 8);
  printstate("init 1st key xor", s);
  P(s, 12);
  s->x[2] ^= key->x[0];
  s->x[3] ^= key->x[1];
  s->x[4] ^= key->x[2];
  printstate("init 2nd key xor", s);
}

forceinline void ascon_adata(ascon_state_t* s, const uint8_t* ad,
                             uint64_t adlen) {
  const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;
  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_AEAD_RATE) {
      s->x[0] ^= LOAD(ad, 8);
      if (ASCON_AEAD_RATE == 16) s->x[1] ^= LOAD(ad + 8, 8);
      printstate("absorb adata", s);
      P(s, nr);
      ad += ASCON_AEAD_RATE;
      adlen -= ASCON_AEAD_RATE;
    }
    /* final associated data block */
    uint64_t* px = &s->x[0];
    if (ASCON_AEAD_RATE == 16 && adlen >= 8) {
      s->x[0] ^= LOAD(ad, 8);
      px = &s->x[1];
      ad += 8;
      adlen -= 8;
    }
    *px ^= PAD(adlen);
    if (adlen) *px ^= LOADBYTES(ad, adlen);
    printstate("pad adata", s);
    P(s, nr);
  }
  /* domain separation */
  s->x[4] ^= 1;
  printstate("domain separation", s);
}

forceinline void ascon_encrypt(ascon_state_t* s, uint8_t* c, const uint8_t* m,
                               uint64_t mlen) {
  const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;
  /* full plaintext blocks */
  while (mlen >= ASCON_AEAD_RATE) {
    s->x[0] ^= LOAD(m, 8);
    STORE(c, s->x[0], 8);
    if (ASCON_AEAD_RATE == 16) {
      s->x[1] ^= LOAD(m + 8, 8);
      STORE(c + 8, s->x[1], 8);
    }
    printstate("absorb plaintext", s);
    P(s, nr);
    m += ASCON_AEAD_RATE;
    c += ASCON_AEAD_RATE;
    mlen -= ASCON_AEAD_RATE;
  }
  /* final plaintext block */
  uint64_t* px = &s->x[0];
  if (ASCON_AEAD_RATE == 16 && mlen >= 8) {
    s->x[0] ^= LOAD(m, 8);
    STORE(c, s->x[0], 8);
    px = &s->x[1];
    m += 8;
    c += 8;
    mlen -= 8;
  }
  *px ^= PAD(mlen);
  if (mlen) {
    *px ^= LOADBYTES(m, mlen);
    STOREBYTES(c, *px, mlen);
  }
  printstate("pad plaintext", s);
}

forceinline void ascon_decrypt(ascon_state_t* s, uint8_t* m, const uint8_t* c,
                               uint64_t clen) {
  const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;
  /* full ciphertext blocks */
  while (clen >= ASCON_AEAD_RATE) {
    uint64_t cx = LOAD(c, 8);
    s->x[0] ^= cx;
    STORE(m, s->x[0], 8);
    s->x[0] = cx;
    if (ASCON_AEAD_RATE == 16) {
      cx = LOAD(c + 8, 8);
      s->x[1] ^= cx;
      STORE(m + 8, s->x[1], 8);
      s->x[1] = cx;
    }
    printstate("insert ciphertext", s);
    P(s, nr);
    m += ASCON_AEAD_RATE;
    c += ASCON_AEAD_RATE;
    clen -= ASCON_AEAD_RATE;
  }
  /* final ciphertext block */
  uint64_t* px = &s->x[0];
  if (ASCON_AEAD_RATE == 16 && clen >= 8) {
    uint64_t cx = LOAD(c, 8);
    s->x[0] ^= cx;
    STORE(m, s->x[0], 8);
    s->x[0] = cx;
    px = &s->x[1];
    m += 8;
    c += 8;
    clen -= 8;
  }
  *px ^= PAD(clen);
  if (clen) {
    uint64_t cx = LOADBYTES(c, clen);
    *px ^= cx;
    STOREBYTES(m, *px, clen);
    *px = CLEAR(*px, clen);
    *px ^= cx;
  }
  printstate("pad ciphertext", s);
}

forceinline void ascon_final(ascon_state_t* s, const ascon_key_t* key) {
  s->x[1] ^= KEYROT(key->x[0], key->x[1]);
  s->x[2] ^= KEYROT(key->x[1], key->x[2]);
  s->x[3] ^= KEYROT(key->x[2], 0);
  printstate("final 1st key xor", s);
  P(s, 12);
  s->x[3] ^= key->x[1];
  s->x[4] ^= key->x[2];
  printstate("final 2nd key xor", s);
}

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  ascon_state_t s;
  (void)nsec;
  *clen = mlen + CRYPTO_ABYTES;
  /* perform ascon computation */
  ascon_key_t key;
  ascon_loadkey(&key, k);
  ascon_initaead(&s, &key, npub);
  ascon_adata(&s, ad, adlen);
  ascon_encrypt(&s, c, m, mlen);
  ascon_final(&s, &key);
  /* set tag */
  STOREBYTES(c + mlen, s.x[3], 8);
  STOREBYTES(c + mlen + 8, s.x[4], 8);
  return 0;
}

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  ascon_state_t s;
  (void)nsec;
  if (clen < CRYPTO_ABYTES) return -1;
  *mlen = clen = clen - CRYPTO_ABYTES;
  /* perform ascon computation */
  ascon_key_t key;
  ascon_loadkey(&key, k);
  ascon_initaead(&s, &key, npub);
  ascon_adata(&s, ad, adlen);
  ascon_decrypt(&s, m, c, clen);
  ascon_final(&s, &key);
  /* verify tag (should be constant time, check compiler output) */
  s.x[3] ^= LOADBYTES(c + clen, 8);
  s.x[4] ^= LOADBYTES(c + clen + 8, 8);
  return NOTZERO(s.x[3], s.x[4]);
}

void print(unsigned char c, unsigned char* x, unsigned long long xlen) {
  unsigned long long i;
  printf("%c[%d]=", c, (int)xlen);
  for (i = 0; i < xlen; ++i) printf("%02x", x[i]);
  printf("\n");
}

int main() {
  unsigned char n[CRYPTO_NPUBBYTES];
  unsigned char k[CRYPTO_KEYBYTES] = "XXXXXXXXXXXXXXXXXXXX";
  unsigned char a[16] = "abc123";
  unsigned char c[1040], h[32], t[32];
  unsigned long long alen = 16;
  unsigned long long mlen = 16;
  unsigned long long clen = CRYPTO_ABYTES;
  
  unsigned char cipher[CRYPTO_BYTES];

  int result = 0;
    
  if (sodium_init() < 0) {
        printf("panic! the library couldn't be initialized; it is not safe to use");
  	return 0;
  }
  
  // Declare file pointers.
  FILE *fp_in, *fp_out, *hacklab_in, *fp_decrypt;
  const size_t chunksize = 1024;
  unsigned char filesize[16];
  unsigned char plaintext[1024];

  // Open the input file.
  fp_in = fopen("public.key", "rb");

  // Check if the file was opened successfully.
  if (fp_in == NULL) {
    printf("Error opening file.\n");
    return 1;
  }

  // Open the output file.
  fp_out = fopen("public.key.hacklab", "wb");

  // Check if the file was opened successfully.
  if (fp_out == NULL) {
    printf("Error opening file.\n");
    return 1;
  }

  // Write the nonce to the output file.
  randombytes_buf(n, sizeof(n));
  fwrite(n, sizeof(unsigned char), sizeof(n), fp_out);

  printf("\n");
  print('n', n, CRYPTO_NPUBBYTES);

  printf("\n[*] Attempting to encrypt public key\n");

  int bytes_read;
  while ((bytes_read = fread(plaintext, 1, 1024, fp_in)) > 0) {

	result |= crypto_aead_encrypt(c, &clen, plaintext, bytes_read, a, alen, (void*)0, n, k);

        fwrite(c, 1, clen, fp_out);
  }

  printf("\n[+] Public key encrypted\n");

  fclose(fp_in);
  fclose(fp_out);

  // Open the input file.
  hacklab_in = fopen("public.key.hacklab", "rb");

  // Check if the file was opened successfully.
  if (hacklab_in == NULL) {
    printf("Error opening file.\n");
    return 1;
  }

  // Open the decrypt file.
  fp_decrypt = fopen("decrypt.key", "wb");

  // check if the file was opened successfully.
  if (fp_decrypt == NULL) {
    printf("Error opening file.\n");
    return 1;
  }

  // Reading nonce from encrypted file
  char nonce[16];
  unsigned char ciphertext2[1040];
  unsigned char plaintext2[1024];

  // Read the file size and IV from the input file.
  fread(nonce, sizeof(char), sizeof(nonce), hacklab_in);

  printf("\n");
  print('n', nonce, CRYPTO_NPUBBYTES);
  
  printf("\n[*] Decrypting public key hacklab\n");

  int bytes_read2;
  while ((bytes_read2 = fread(ciphertext2, 1, 1040, hacklab_in)) > 0) {

	result |= crypto_aead_decrypt(plaintext2, &mlen, (void*)0, ciphertext2, bytes_read2, a, alen, nonce, k);

        fwrite(plaintext2, 1, mlen, fp_decrypt);
  }

  printf("\n[+] Public key hacklab decrypted\n\n");

  //Close the files.
  fclose(hacklab_in);
  fclose(fp_decrypt);

  return 0;
}
