# SMAUG, Pushing Lattice-based Key Encapsulation Mechanisms to the Limits

**SMAUG** is a new post-quantum KEM scheme whose IND-CCA2 security is based on the combination of MLWE and MLWR problems.

**SMAUG** achieves ciphertext sizes up to 12% and 9% smaller than Kyber and Saber, with much faster running time, up to 103% and 58%, respectively.
Compared to Sable, **SMAUG** has the same ciphertext sizes but a larger public key, which gives a trade-off between the public key size versus performance;
**SMAUG** has 39%-55% faster encapsulation and decapsulation speed in the parameter sets having comparable security.

## How to build and test
```bash
# build
$ cmake -S ./ -B build
$ cmake --build build -j


# test
$ cd ./build/bin
$ ./smaug1-main
```