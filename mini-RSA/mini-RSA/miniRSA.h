#pragma once
#include <iostream>
#include <ctime>
#include <cstdlib>
#include <tuple>

long long unsigned mypow(const long long unsigned& num, const long long unsigned& deg) {
    if (deg == 0)
        return 1;
    long long buf = num;
    for (size_t i = 1; i < deg; ++i)
    {
        buf *= num;
    }
    return buf;
}


long long unsigned gcd(long long unsigned a, long long unsigned b, long long& x, long long& y) {
    x = 1, y = 0;
    long long unsigned x1 = 0;
    long long unsigned y1 = 1;
    while (b) {
        long long unsigned q = a / b;
        std::tie(x, x1) = std::make_tuple(x1, x - q * x1);
        std::tie(y, y1) = std::make_tuple(y1, y - q * y1);
        std::tie(a, b) = std::make_tuple(b, a - q * b);
    }
    return a;
}



class PrivateKey {
    long long unsigned p = 2;
    long long unsigned q = 17;
    long long d;
    long long e;
public:
    PrivateKey();
    const long long unsigned getN() { return p * q; };
    const long long unsigned getE() { return e; };
    long long DecryptMessenge(const long long unsigned& num);
    const long long getCertificate(long long unsigned num) { return mypow(num, d) % getN(); }
};

PrivateKey::PrivateKey()
{
    for (size_t i = 2; i < (p - 1) * (q - 1); i++)
    {
        if ((p - 1) * (q - 1) % i) {
            e = i;
            break;
        }
    }
    d = 0;
    long long y = 0;
    gcd((p - 1) * (q - 1), e, y, d);
    d = (d < 0) ? (d + (p - 1) * (q - 1)) : d;
}



long long PrivateKey::DecryptMessenge(const long long unsigned& num)
{
    return mypow(num, d) % getN();
}


class PublicKey {
    long long unsigned n;
    long long unsigned e;
public:
    PublicKey(PrivateKey private_key);
    long long EncryptMessenge(const long long unsigned& num);
    const bool CheckCertificate(const long long unsigned& m, const long long unsigned& s) { return ((mypow(s, e) - m) % n == 0) ? 1 : 0; }
};
PublicKey::PublicKey(PrivateKey private_key)
{
    n = private_key.getN();
    e = private_key.getE();
}

long long PublicKey::EncryptMessenge(const long long unsigned& num)
{
    return mypow(num, e) % n;
}