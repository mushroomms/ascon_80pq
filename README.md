# ascon_c

Ascon_80pq C implementation with libsodium which generates a random nonce that is safe to use for cryptography
<br><br>
The current repository contains the code which measures:
1. CPU Cycles per bytes
2. CPU Time
3. Wall Time

To compile both encrypt.c & decrypt.c, simply run the Makefile:
```
make all
```
Simply clean by running:
```
make clean
```

## Usage
Usage of encrypt.c:
```
./encrypt <plaintext file> <encrypted file> <key file>
```
Usage of decrypt.c:
```
./decrypt <encrypted file> <plaintext file> <key file>
```

## Libsodium installation
Download a [tarball of libsodium](https://download.libsodium.org/libsodium/releases/), preferably the latest stable version, then follow the ritual:

```
./configure
make && make check
sudo make install
source ~/.bashrc
```
