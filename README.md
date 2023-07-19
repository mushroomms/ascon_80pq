# ascon_c

Ascon C implementation with libsodium which generates a random string that is safe to use for cryptography

To compile the file:

```
gcc main.c permutations.c printstate.c -o ascon -lsodium
```

## Libsodium installation
Download a [tarball of libsodium](https://download.libsodium.org/libsodium/releases/), preferably the latest stable version, then follow the ritual:

```
./configure
make && make check
sudo make install
```
