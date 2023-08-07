# ascon_c

Ascon_80pq C implementation with libsodium which generates a random nonce that is safe to use for cryptography

To compile the file:

```
gcc main.c permutations.c printstate.c -o ascon -lsodium
```

To compile file encryption and decrypton code:
```
gcc encrypt.c permutations.c printstate.c -o encrypt -lsodium
```
```
gcc decrypt.c permutations.c printstate.c -o decrypt -lsodium
```

## Test Speed
The folder Test Speed contains the code which measures:
1. CPU Cycles per bytes
2. CPU Time
3. Wall Time

## Libsodium installation
Download a [tarball of libsodium](https://download.libsodium.org/libsodium/releases/), preferably the latest stable version, then follow the ritual:

```
./configure
make && make check
sudo make install
source ~/.bashrc
```
