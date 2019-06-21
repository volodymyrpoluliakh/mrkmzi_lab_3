#ifndef EL_GAMAL_HPP
#define EL_GAMAL_HPP
#include <gmp.h>
#include <gmpxx.h>
#include <vector>

mpz_class generate_prime_by_length(uint64_t length);


struct PublicKey {
    mpz_class p;
    mpz_class g;
    mpz_class y;
};

struct PrivateKey {
    mpz_class x;
};

struct DigitalSignature {
    mpz_class a;
    mpz_class b;
};

class KeyPair {
public:
    KeyPair(uint64_t p_length);
    KeyPair(const mpz_class& p, const mpz_class& g, const mpz_class& y, const mpz_class& x);

    const PublicKey& public_key() const { return _public_key; }
    const PrivateKey& private_key() const { return _private_key; }

private:
    PublicKey  _public_key;
    PrivateKey _private_key;
};

struct CipherText {
    mpz_class a;
    mpz_class b;
};

namespace el_gamal {
   DigitalSignature sign(const mpz_class& message, const KeyPair& key_pair);
   bool verify(const mpz_class& message, const DigitalSignature& digital_sign, const PublicKey& public_key);
   CipherText encrypt(const mpz_class& message, const PublicKey& public_key);
   mpz_class decrypt(const CipherText& ct, const KeyPair& key_pair);
}


KeyPair generate_key_pair_by_length(uint64_t length);

uint64_t getNumOfPrt();

std::vector<uint64_t> generateL89(uint64_t size, bool isP);

std::string vecui_to_str(const std::vector<uint64_t>& vecui);

mpz_class generate_prime_by_length(uint64_t length);


#endif // EL_GAMAL_HPP
