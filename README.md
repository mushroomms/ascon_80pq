# ascon_c

Ascon_80pq C implementation with libsodium which generates a random nonce that is safe to use for cryptography

To compile the ref:

```
gcc main.c permutations.c printstate.c -o ascon -lsodium
```

## Test Speed
The folder Test Speed contains the code which measures:
1. CPU Cycles per bytes
2. CPU Time
3. Wall Time

To run test_speed, simply run the Makefile:
```
make all
```
After running test_speed, simply clean by running:
```
make clean
```

## Libsodium installation
Download a [tarball of libsodium](https://download.libsodium.org/libsodium/releases/), preferably the latest stable version, then follow the ritual:

```
./configure
make && make check
sudo make install
source ~/.bashrc
```
