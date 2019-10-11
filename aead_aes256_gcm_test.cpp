// 依赖的软件包:
// Ubuntu: sudo apt install libbotan-2-dev
// Fedora: dnf install botan2-devel

// g++编译源码, 生成a.out:
//     g++ `pkg-config --cflags botan-2` aead_aes256_*_test.cpp `pkg-config --libs botan-2`

// 运行可执行文件a.out:
// ./a.out
//    AEAD Cipher name and mode: AES-256/GCM(16)
//    Plain data(16 bytes): F56E87055BC32D0EEB31B2EACC2BF2A5
//    Key: EEBC1F57487F51921C0465665F8AE6D1658BB26DE6F8A069A3520293A572078F
//    Prepared associated data:
//    Random IV: 99AA3E68ED8173A0EED06684, (12 bytes)
//    Encrypted data with tag(32 bytes in hex format): F7264413A84C0E7CD536867EB9F2173667BA0510262AE487D737EE6298F77E0C
//    GCM tag(16 bytes in hex format): 67BA0510262AE487D737EE6298F77E0C
//    GCM Tag OK!
//
//
// 代码节选自 Botan-handbook, 有修改
// 原文网址 https://botan.randombit.net/handbook/api_ref/cipher_modes.html#aead-mode



#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>

#if defined(BOTAN_HAS_AEAD_MODES)
  #include <botan/aead.h>
#else
  #error "AEAD Mode is not enabled!"
#endif

//#if defined(BOTAN_HAS_SM4)
//  #include <botan/sm4.h>
//#endif

#include <cstdio> // <stdio.h>

// FIPS(美国)联邦信息处理标准AES-256-GCM测试用例
// 源代码取自 https://github.com/openssl/openssl/blob/OpenSSL_1_1_1d/demos/evp/aesgcm.c
//static const unsigned char gcm_key[] = {
//    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
//    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
//    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
//};

static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

static const unsigned char gcm_plaintext[] = {
    0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
    0xcc, 0x2b, 0xf2, 0xa5
};

static const unsigned char gcm_aad[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
    0x7f, 0xec, 0x78, 0xde
};

static const unsigned char expected_gcm_ciphertext[] = {
    0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e,
    0xb9, 0xf2, 0x17, 0x36
};

static const unsigned char expected_gcm_tag_aes256[] = {
    0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
    0x98, 0xf7, 0x7e, 0x0c
};







void run_test_AEAD_AES256_GCM(void)
{
    Botan::AutoSeeded_RNG rng;

    const long unsigned plaintext_len = sizeof gcm_plaintext;
    uint8_t plaintext[plaintext_len];
    memcpy(plaintext, gcm_plaintext, plaintext_len);

    const char aead_cipher_name[] = "AES-256/GCM"; //"SM4/GCM"
#if BOTAN_VERSION_MAJOR >= 2 && BOTAN_VERSION_MINOR >= 6
    std::unique_ptr<Botan::AEAD_Mode> aead =
        Botan::AEAD_Mode::create(aead_cipher_name, Botan::ENCRYPTION);
#else
    Botan::AEAD_Mode *aead =
        Botan::get_aead(aead_cipher_name, Botan::ENCRYPTION);
#endif

    std::vector<uint8_t> key = /* FIPS(美国)联邦信息处理标准AES-256-GCM测试用例 */
        Botan::hex_decode("eebc1f57487f51921c0465665f8ae6d1658bb26de6f8a069a3520293a572078f");
    if (key.size() < aead->key_spec().minimum_keylength()) {
        fprintf(stderr, "ERROR: key length = %ld, but minimum required is %ld\n", key.size(), aead->key_spec().minimum_keylength());
    }
    aead->set_key(key);

    // Generate fresh nonce (IV)
    Botan::secure_vector<uint8_t> iv(gcm_iv, gcm_iv+sizeof gcm_iv);

    aead->set_associated_data(gcm_aad, sizeof gcm_aad);
    aead->start(iv);


    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> buf(plaintext, plaintext+16);
    aead->finish(buf);

    using std::printf;
    std::vector<uint8_t> data(plaintext, (plaintext + plaintext_len));
    std::vector<uint8_t> aad(gcm_aad, (gcm_aad + sizeof gcm_aad));
    printf("AEAD Cipher name and mode: %s\n", aead->name().c_str());
    printf("Plain data(%lu bytes): %s\n", plaintext_len, Botan::hex_encode(data).c_str());
    printf("Key: %s\n", Botan::hex_encode(key).c_str());
    printf("Static associated data: %s, (%lu bytes)\n", Botan::hex_encode(aad).c_str(), aad.size());
    printf("Static IV: %s, (%lu bytes)\n", Botan::hex_encode(iv).c_str(), iv.size());
    printf("Encrypted data with tag(%lu bytes in hex format): %s\n", buf.size(), Botan::hex_encode(buf).c_str());
    if (memcmp(buf.data(), expected_gcm_ciphertext, sizeof expected_gcm_ciphertext) == 0) {
        printf("Ciphertext OK!\n");
    } else {
        printf("ERROR: Ciphertext mismatch!!\n");
    }
    std::vector<uint8_t> tag(buf.data()+buf.size()-aead->tag_size(), buf.data()+buf.size());
    printf("GCM tag(%lu bytes in hex format): %s\n", tag.size(), Botan::hex_encode(tag).c_str());
    if (memcmp(tag.data(), expected_gcm_tag_aes256, aead->tag_size()) == 0) {
        printf("GCM tag OK!\n");
    } else {
        printf("ERROR: GCM tag mismatch!!\n");
    }
}

int main()
{
    try {
        run_test_AEAD_AES256_GCM();
    } catch (const std::exception& e) {
        fprintf(stderr, "ERR: %s\n", e.what());
    }

    return 0;
}
