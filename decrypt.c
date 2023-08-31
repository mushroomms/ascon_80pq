#include "lib/api.h"
#include "lib/ascon.h"
#include "lib/crypto_aead.h"

#include <string.h>
#include <stdio.h>
#include <sodium.h>
#include <time.h>
#include <x86intrin.h>

#define CHUNK_SIZE 4096

#define cpucycles(cycles) cycles = __rdtsc()
#define cpucycles_reset() cpucycles_sum = 0
#define cpucycles_start() cpucycles(cpucycles_before)
#define cpucycles_stop()                                 \
  do                                                     \
  {                                                      \
    cpucycles(cpucycles_after);                          \
    cpucycles_sum += cpucycles_after - cpucycles_before; \
  } while (0)

#define cpucycles_result() cpucycles_sum

size_t rlen_total;
double total_cpucycles;
struct timespec begin_cpu, end_cpu, begin_wall, end_wall;
unsigned long long cpucycles_before, cpucycles_after, cpucycles_sum;

char *showhex(uint8_t a[], int size);

char *showhex(uint8_t a[], int size) {
      char *s = malloc(size * 2 + 1);
      for (int i = 0; i < size; i++)
            sprintf(s + i * 2, "%02x", a[i]);
      return (s);
}

static int decrypt(const char *target_file, const char *source_file, const char *pmk_keyfile) {
  #define ADDITIONAL_DATA (const unsigned char *)"123456"
  #define ADDITIONAL_DATA_LEN 6

  unsigned char buf_in[CHUNK_SIZE + CRYPTO_ABYTES];
  unsigned char buf_out[CHUNK_SIZE];
  unsigned char nonce[CRYPTO_NPUBBYTES];
  unsigned char key[CRYPTO_KEYBYTES];

  unsigned long long out_len;
  size_t  rlen;

  FILE *pmk_key = fopen(pmk_keyfile, "rb");
  if (pmk_key == NULL) {
    printf("\nPMK Key with the file name [%s] cannot be found!\n", pmk_keyfile);
    return 1;
  }

  FILE *fp_s = fopen(source_file, "rb");
  if (fp_s == NULL) {
    printf("\nSource file to be dencrypted with the file name [%s] cannot be found!\n", source_file);
    return 1;
  }

  FILE *fp_t = fopen(target_file, "wb");
  if (fp_t == NULL) {
    printf("\nTarger file with the file name [%s] cannot be created!\n", target_file);
    return 1;
  }

  fread(nonce, sizeof(unsigned char), CRYPTO_NPUBBYTES, fp_s); // Writing nonce into file
  fread(key, 1, CRYPTO_KEYBYTES, pmk_key); // Reading PMK key file

  printf("\nKey: %s\n", showhex(key, CRYPTO_KEYBYTES));
  printf("Nonce: %s\n", showhex(nonce, CRYPTO_NPUBBYTES));

  printf("\n[*] Attempting to decrypt [%s]\n", source_file);

  clock_gettime(CLOCK_REALTIME, &begin_wall);
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &begin_cpu);

  while(rlen = fread(buf_in, 1, sizeof buf_in, fp_s)) {
    cpucycles_reset();
    cpucycles_start();
    crypto_aead_decrypt(buf_out, &out_len, (void*)0, buf_in, rlen, ADDITIONAL_DATA, ADDITIONAL_DATA_LEN, nonce, key);
    cpucycles_stop();

    fwrite(buf_out, 1, (size_t)out_len, fp_t);

    total_cpucycles += cpucycles_result();
    rlen_total += rlen;
  }

  clock_gettime(CLOCK_REALTIME, &end_wall);
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_cpu);

  fclose(fp_t);
  fclose(fp_s);
  fclose(pmk_key);
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc != 4) {
    printf("Usage: %s <ENCRYPTED_FILENAME> <PLAINTEXT_FILENAME> <KEY>\n", argv[0]);
    return 1;
  }

  char *ENCRYPTED_HACKLAB = argv[1];
  char *KEY_NAME = argv[2];
  char *PMK_KEY = argv[3];

  if (decrypt(KEY_NAME, ENCRYPTED_HACKLAB, PMK_KEY) != 0) {
    return 1;
  }

  printf("\n[+] [%s] decrypted to [%s] successfully\n", ENCRYPTED_HACKLAB, KEY_NAME);

  double total_time_cpu = (end_cpu.tv_sec - begin_cpu.tv_sec) + (end_cpu.tv_nsec - begin_cpu.tv_nsec) / 1000000000.0;
  double total_time_wall = (end_wall.tv_sec - begin_wall.tv_sec) + (end_wall.tv_nsec - begin_wall.tv_nsec) / 1000000000.0;

  printf("\nWALL time: %f seconds\n", total_time_wall);
  printf("CPU time: %f seconds\n", total_time_cpu);

  printf("\nTotal CPU Cycles: %.0f\n", total_cpucycles);
  printf("CPU Cycles/Bytes: %f\n", total_cpucycles / rlen_total);

  return 0;
}