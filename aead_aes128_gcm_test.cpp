// 文件名: aead_aes128_gcm_test.cpp
// 编译命令:
//     g++ `pkg-config --cflags botan-2` aead_*_test.cpp `pkg-config --libs botan-2`
//
// 代码节选自 Botan-handbook, 有修改
// 原文网址 https://botan.randombit.net/handbook/api_ref/cipher_modes.html#aead-mode
// 依赖的软件包:
// sudo apt install libbotan-2-dev

#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>

#if defined(BOTAN_HAS_AEAD_MODES)
  #include <botan/aead.h>
#else
  #error "AEAD Mode is not enabled!"
#endif

#include <cstdio> // <stdio.h>

int main()
{
    Botan::AutoSeeded_RNG rng;

    const std::string plaintext(
        "Your great-grandfather gave this watch to your granddad for good luck.\n"
        "Unfortunately, Dane's luck wasn't as good as his old man's.\n"
        );
    const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");

    Botan::Cipher_Mode *aead =
        Botan::get_aead("AES-128/GCM", Botan::ENCRYPTION);
    aead->set_key(key);

    // Generate fresh nonce (IV)
    Botan::secure_vector<uint8_t> iv = rng.random_vec(aead->default_nonce_length());

    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data()+plaintext.length());
    printf("Plaintext message (in ASCII): %s\n", plaintext.c_str());

    aead->start(iv);
    aead->finish(pt);

    using std::printf;
    printf("AEAD Cipher name and mode: %s\n", aead->name().c_str());
    printf("Random key: %s\n", Botan::hex_encode(key).c_str());
    printf("Random IV: %s\n", Botan::hex_encode(iv).c_str());
    printf("Encrypted data (in hex format): %s\n", Botan::hex_encode(pt).c_str());
    return 0;
}
