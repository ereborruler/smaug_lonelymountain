#include "ciphertext.h"
#include "indcpa.h"
#include "io.h"
#include "kem.h"
#include "pack.h"
#include "parameters.h"
#include "poly.h"
#include "rng.h"
#include <stdio.h>
#include <time.h>

#define m_size 10

int indcpa_test();
int kem_test();

int main(void) {
    time_t mytime = time(NULL);
    char *time_str = ctime(&mytime);
    time_str[strlen(time_str) - 1] = '\0';
    printf("\n*** %s with mode %d starts at %s\n", "SMAUG KEM", SMAUG_MODE,
           time_str);

    size_t count = 1;
    const size_t iteration = 1000;

    uint8_t entropy_input[48] = {0};
    for (size_t i = 0; i < 48; ++i) {
        entropy_input[i] = i;
    }
    randombytes_init(entropy_input, NULL, 256);

    for (size_t i = 0; i < iteration; ++i) {
        if (!(i % (iteration / 10))) {
            printf("...%lu%%", count * 10);
            fflush(stdout);
            ++count;
        }

        // if (indcpa_test()) {
        //     printf("PKE test fails at %lu-th tries\n", i);
        //     break;
        // }

        if (kem_test()) {
            printf("KEM test fails at %lu-th tries\n", i);
            break;
        }
    }

    return 0;
}

int indcpa_test() {
    uint8_t pk[PUBLICKEY_BYTES] = {0};
    uint8_t sk[PKE_SECRETKEY_BYTES] = {0};
    uint8_t ctxt[CIPHERTEXT_BYTES] = {0};
    uint8_t mu[DELTA_BYTES] = {0}, mu2[DELTA_BYTES] = {0};
    uint8_t seed[DELTA_BYTES] = {0};

    randombytes(mu, DELTA_BYTES);
    randombytes(seed, DELTA_BYTES);

    indcpa_keypair(pk, sk);
    indcpa_enc(ctxt, pk, mu, seed);
    indcpa_dec(mu2, sk, ctxt);

    if (memcmp(mu, mu2, DELTA_BYTES) != 0)
        return 1;

    return 0;
}

int kem_test() {
    uint8_t pk[PUBLICKEY_BYTES] = {0};
    uint8_t sk[KEM_SECRETKEY_BYTES] = {0};
    uint8_t ctxt[CIPHERTEXT_BYTES] = {0};
    uint8_t ss[CRYPTO_BYTES] = {0}, ss2[CRYPTO_BYTES] = {0};

    crypto_kem_keypair(pk, sk);
    crypto_kem_encap(ctxt, ss, pk);
    int res = crypto_kem_decap(ss2, sk, pk, ctxt);

    if (memcmp(ss, ss2, CRYPTO_BYTES) != 0)
        res = 1;

    return res;
}
