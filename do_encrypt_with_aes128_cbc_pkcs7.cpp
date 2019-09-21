// 代码节选自 Botan-handbook, 有修改
// 原文网址 https://botan.randombit.net/handbook/api_ref/cipher_modes.html#aead-mode

#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <cstdio> // <stdio.h>

int main()
{
    Botan::AutoSeeded_RNG rng;

    const std::string plaintext(
        "Your great-grandfather gave this watch to your granddad for good luck.\n"
        "Unfortunately, Dane's luck wasn't as good as his old man's.\n"
        );
    const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");

    std::unique_ptr<Botan::Cipher_Mode> enc =
        Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::ENCRYPTION);
    enc->set_key(key);

    // Generate fresh nonce (IV)
    Botan::secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());

    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data()+plaintext.length());
    printf("Plaintext message (in ASCII): %s\n", plaintext.c_str());

    enc->start(iv);
    enc->finish(pt);

    using std::printf;
    printf("Cipher name and mode: %s\n", enc->name().c_str());
    printf("Random key: %s\n", Botan::hex_encode(key).c_str());
    printf("Random IV: %s\n", Botan::hex_encode(iv).c_str());
    printf("Encrypted data (in hex format): %s\n", Botan::hex_encode(pt).c_str());
    return 0;
}
