#include "pch.h"
#include "../mini-RSA/miniRSA.h"

PrivateKey priv;
PublicKey pub(priv);

TEST(Test1, EqualsMesAndDecMes) {
    int enc = pub.EncryptMessenge(5);
    ASSERT_EQ(5, priv.DecryptMessenge(enc));
}

TEST(Test2, EqualsMesAndDecMes) {
    int enc = pub.EncryptMessenge(7);
    ASSERT_EQ(7, priv.DecryptMessenge(enc));
}

TEST(Test3, EqualsMesAndDecMes) {
    int enc = pub.EncryptMessenge(27);
    ASSERT_EQ(27, priv.DecryptMessenge(enc));
}

TEST(Test4, CERTIFICATE) {
    long long unsigned s = priv.getCertificate(5);
    ASSERT_TRUE(pub.CheckCertificate(5, s));
}

TEST(Test5, CERTIFICATE) {
    long long unsigned s = priv.getCertificate(7);
    ASSERT_TRUE(pub.CheckCertificate(7, s));
}

TEST(Test6, CERTIFICATE) {
    long long unsigned s = priv.getCertificate(27);
    ASSERT_TRUE(pub.CheckCertificate(27, s));
}

