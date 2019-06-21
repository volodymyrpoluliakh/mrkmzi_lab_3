#include "el_gamal.hpp"
#include <sstream>
#include <iomanip>
#include <iostream>

uint64_t getNumOfPrt(){
   uint64_t res;
   asm __volatile__(
    "xor %%rax, %%rax\n\t"
    "rdtsc\n\t"
    "shl $32, %%rdx\n\t"
    "or %%rdx, %%rax\n\t"
    "mov %%rax, %0"
    : "=r" (res)
    :
    : "rdx"
   );
   return res;
}

std::vector<uint64_t> generateL89(uint64_t size, bool isP){
    uint64_t* state = new uint64_t[2];
    state[0] = 0;
    state[1] = 0;

    for(int i = 0; i < 2; i++){
        for(int j = 0; j < 8; j++){
            uint64_t rd = getNumOfPrt();
            state[i] = (state[i] << 8) | (rd & 0xFF);
        }
    }

    uint64_t arrLen = 0;
    if (size % 64 == 0){
        arrLen = (size / 64);
    }
    else {
        arrLen = (size / 64) + 1;
    }
    uint64_t* l89 = new uint64_t[arrLen];

    uint64_t buf;
    for(int i = 0; i < 1000; i++){
        buf = (((state[0] >> 23) ^ (state[1] >> 37)) & 1);
        state[0] = (state[0] << 1) | (state[1] >> 63);
        state[1] = (state[1] << 1) | buf;
    }

    uint64_t len = size / 64;
    for(int i = 0; i < len; i++){
        for(int j = 0; j < 64; j++ ){
            buf = (((state[0] >> 23) ^ (state[1] >> 37)) & 1);
            state[0] = (state[0] << 1) | (state[1] >> 63);
            state[1] = (state[1] << 1) | buf;
        }
        l89[i] = state[0];
    }

    if(size % 64 != 0){
        l89[arrLen - 1] = 0;
        buf = 0;
        uint64_t lastDigit{};
        for(int i = 0; i < size % 64; i++){
            buf = (((state[0] >> 23) ^ (state[1] >> 37)) & 1);
            state[0] = (state[0] << 1) | (state[1] >> 63);
            state[1] = (state[1] << 1) | buf;
            lastDigit = (lastDigit << 1) | buf;
        }
        l89[arrLen - 1] = lastDigit;
    }

    if (isP){
        l89[arrLen - 1] = l89[arrLen - 1] | ((uint64_t) 1 << ((size % 64) - 1));
        l89[0] = l89[0] | 1;
    }
    std::vector<uint64_t> vec_L89 = std::vector<uint64_t> (l89, l89 + arrLen);

    delete [] state;
    delete [] l89;

    return vec_L89;
}

std::string vecui_to_str(const std::vector<uint64_t>& vecui) {
    std::stringstream ss;
    ss << std::hex << vecui.front();
    for (auto it = vecui.begin() + 1; it != vecui.end(); ++it) {
      ss << std::setfill('0') << std::setw(8) << std::hex << *it;
    }
    return ss.str();
}


mpz_class generate_prime_by_length(uint64_t length) {
    if (length != 128 && length != 256 && length != 512 && length != 1024 && length != 2048 && length != 4096 && length != 8192) {
        throw std::runtime_error("Wrong key length given! Aborting...");
    }

    mpz_class key;

    int is_prime = 0;
    while (!is_prime) {
        auto vec_key = generateL89(length, true);
        mpz_set_str(key.get_mpz_t(), vecui_to_str(vec_key).c_str(), 16);
        is_prime = mpz_probab_prime_p(key.get_mpz_t(), 50);
    }

    return key;
}



KeyPair::KeyPair(uint64_t p_length) {
    _public_key.p = generate_prime_by_length(p_length);

    gmp_randstate_t state;
    gmp_randinit_default(state);

    mpz_urandomm(_public_key.g.get_mpz_t(), state, _public_key.p.get_mpz_t());
    mpz_urandomm(_private_key.x.get_mpz_t(), state, _public_key.p.get_mpz_t());

    mpz_powm_sec(_public_key.y.get_mpz_t(), _public_key.g.get_mpz_t(), _private_key.x.get_mpz_t(), _public_key.p.get_mpz_t());
}

KeyPair::KeyPair(const mpz_class& p, const mpz_class& g, const mpz_class& y, const mpz_class& x)
    : _public_key({p, g, y}), _private_key({x})
{}

DigitalSignature el_gamal::sign(const mpz_class& message, const KeyPair& key_pair) {
    mpz_class p_minus_1 = key_pair.public_key().p - 1;

    if (message >= p_minus_1) {
        throw std::runtime_error("Wrong message given! Message is bigger than p - 1. Unable to sign message...");
    }

    mpz_class k;
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, static_cast<long>(getNumOfPrt()));
    gmp_randinit_default(state);
    mpz_class gcd = 0;
    while (gcd != 1) {
        mpz_urandomm(k.get_mpz_t(), state, p_minus_1.get_mpz_t());
        mpz_gcd(gcd.get_mpz_t(), p_minus_1.get_mpz_t(), k.get_mpz_t());
    }

    DigitalSignature digital_sign;


    mpz_powm(digital_sign.a.get_mpz_t(), key_pair.public_key().g.get_mpz_t(),
                 k.get_mpz_t(), key_pair.public_key().p.get_mpz_t());

    mpz_class xa = key_pair.private_key().x * digital_sign.a;
    mpz_sub(digital_sign.b.get_mpz_t(), message.get_mpz_t(), xa.get_mpz_t());
    mpz_mod(digital_sign.b.get_mpz_t(), digital_sign.b.get_mpz_t(), p_minus_1.get_mpz_t());

    mpz_class k_inv;
    mpz_invert(k_inv.get_mpz_t(), k.get_mpz_t(), p_minus_1.get_mpz_t());
//    std::cout << k_inv.get_str(10) << std::endl;

    mpz_mul(digital_sign.b.get_mpz_t(), digital_sign.b.get_mpz_t(), k_inv.get_mpz_t());
    mpz_mod(digital_sign.b.get_mpz_t(), digital_sign.b.get_mpz_t(), p_minus_1.get_mpz_t());

    return  digital_sign;
}

bool el_gamal::verify(const mpz_class& message, const DigitalSignature& digital_sign, const PublicKey& public_key) {
    mpz_class g_deg_m, y_deg_a, a_deg_b, l_res;
    mpz_powm_sec(g_deg_m.get_mpz_t(), public_key.g.get_mpz_t(), message.get_mpz_t(), public_key.p.get_mpz_t());

    mpz_powm(y_deg_a.get_mpz_t(), public_key.y.get_mpz_t(), digital_sign.a.get_mpz_t(), public_key.p.get_mpz_t());
    mpz_powm(a_deg_b.get_mpz_t(), digital_sign.a.get_mpz_t(), digital_sign.b.get_mpz_t(), public_key.p.get_mpz_t());
    mpz_mul(l_res.get_mpz_t(), y_deg_a.get_mpz_t(), a_deg_b.get_mpz_t());
    mpz_mod(l_res.get_mpz_t(), l_res.get_mpz_t(), public_key.p.get_mpz_t());

    return l_res == g_deg_m;
}

CipherText el_gamal::encrypt(const mpz_class& message, const PublicKey& public_key) {
    mpz_class p_minus_1 = public_key.p - 1;

    if (message >= p_minus_1) {
        throw std::runtime_error("Wrong message given! Message is bigger than p - 1. Unable to sign message...");
    }

    CipherText ct;
    mpz_class k;
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, static_cast<long>(getNumOfPrt()));
    gmp_randinit_default(state);
    mpz_class gcd = 0;
    while (gcd != 1) {
        mpz_urandomm(k.get_mpz_t(), state, p_minus_1.get_mpz_t());
        mpz_gcd(gcd.get_mpz_t(), p_minus_1.get_mpz_t(), k.get_mpz_t());
    }

    mpz_powm(ct.a.get_mpz_t(), public_key.g.get_mpz_t(),
             k.get_mpz_t(), public_key.p.get_mpz_t());

    mpz_powm(ct.b.get_mpz_t(), public_key.y.get_mpz_t(), k.get_mpz_t(), public_key.p.get_mpz_t());

    ct.b *= message;

    mpz_mod(ct.b.get_mpz_t(), ct.b.get_mpz_t(), public_key.p.get_mpz_t());

    return ct;
}

mpz_class el_gamal::decrypt(const CipherText& ct, const KeyPair& key_pair) {
    mpz_class message;
    mpz_powm(message.get_mpz_t(), ct.a.get_mpz_t(), key_pair.private_key().x.get_mpz_t(), key_pair.public_key().p.get_mpz_t());
    mpz_invert(message.get_mpz_t(), message.get_mpz_t(), key_pair.public_key().p.get_mpz_t());
    message *= ct.b;
    mpz_mod(message.get_mpz_t(), message.get_mpz_t(), key_pair.public_key().p.get_mpz_t());
    return message;
}
