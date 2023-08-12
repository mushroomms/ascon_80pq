CC = gcc
RM = /bin/rm

all: \
  encrypt \
  decrypt \

encrypt: encrypt.c lib/aead.c
	$(CC) -o encrypt encrypt.c lib/aead.c -lsodium

decrypt: decrypt.c lib/aead.c
	$(CC) -o decrypt decrypt.c lib/aead.c -lsodium

clean:
	-$(RM) -rf encrypt
	-$(RM) -rf decrypt
	-$(RM) -rf decrypt.key
	-$(RM) -rf public.key.hacklab