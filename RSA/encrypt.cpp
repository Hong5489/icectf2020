#include <iostream>
#include <fstream>
#include <cassert>
#include "gmp.h"
#include "gmpxx.h"
using namespace std;

const int bits = 4096;

int main() {
    // Read a cryptographically secure seed from /dev/random
    unsigned int seed;
    ifstream drand("/dev/random", ifstream::binary);
    drand.read((char*)&seed, 4);
    drand.close();

    // Initialize a random number generator with our seed
    gmp_randclass r(gmp_randinit_default);
    r.seed(seed);

    // Let p be a random 4096-bit prime number
    mpz_class p = r.get_z_bits(bits);
    while (!mpz_probab_prime_p(p.get_mpz_t(), 30)) {
        p++;
    }

    // Let q be a random 4096-bit prime number that is not too close to p
    mpz_class q = p ^ (mpz_class(1) << bits);
    while (!mpz_probab_prime_p(q.get_mpz_t(), 30)) {
        q++;
    }

    // Initialize remaining RSA parameters
    mpz_class n = p*q,
              lam = lcm(p-1, q-1),
              e = 65537,
              d;

    assert(gcd(e, lam) == 1);

    mpz_invert(d.get_mpz_t(), e.get_mpz_t(), lam.get_mpz_t());

    // Save public key
    ofstream pub("public.txt");
    pub << "n = " << n << endl;
    pub << "e = " << e << endl;

    // Save private key
    ofstream priv("private.txt");
    priv << "p = " << p << endl;
    priv << "q = " << q << endl;
    priv << "d = " << d << endl;

    // Read message as a base-256 encoded number
    mpz_class m = 0;
    ifstream msg("message.txt");
    char mc;
    while (msg.get(mc)) {
        m = m * 256 + mc;
    }

    assert(m < n);

    // Encrypt message
    mpz_class c;
    mpz_powm(c.get_mpz_t(), m.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());

    // Save encrypted message
    ofstream enc("encrypted.txt");
    enc << c << endl;

    return 0;
}

