CC = gcc
RM = /bin/rm

all: \
  encrypt \
  decrypt \

encrypt: encrypt.c aead.c
	$(CC) -o encrypt encrypt.c aead.c -lsodium

decrypt: decrypt.c aead.c
	$(CC) -o decrypt decrypt.c aead.c -lsodium

clean:
	-$(RM) -rf encrypt
	-$(RM) -rf decrypt