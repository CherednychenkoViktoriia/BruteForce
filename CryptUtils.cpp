#include <string>
#include <exception>
#include <iostream>
#include <vector>

#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/sha.h"

#include "CryptUtils.h"
#include "FsUtils.h"
#include "BruteForce.h"

unsigned char key[EVP_MAX_KEY_LENGTH];
unsigned char iv[EVP_MAX_IV_LENGTH];
bool g_passwordIsNotFound = true;
bool decryptFinalResults = false;

void PasswordToKey(std::string& password)
{
    const EVP_MD* dgst = EVP_get_digestbyname("md5");
    if (!dgst)
    {
        throw std::runtime_error("no such digest");
    }

    const unsigned char* salt = NULL;
    if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
        reinterpret_cast<unsigned char*>(&password[0]),
        password.size(), 1, key, iv))
    {
        throw std::runtime_error("EVP_BytesToKey failed");
    }
}

void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
{
    std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, &data[0], data.size());
    SHA256_Final(&hashTmp[0], &sha256);

    hash.swap(hashTmp);
}

void EncryptAes(const std::vector<unsigned char> plainText, std::vector<unsigned char>& cipherText)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        throw std::runtime_error("EncryptInit error");
    }

    std::vector<unsigned char> cipherTextBuf(plainText.size() + AES_BLOCK_SIZE);
    int cipherTextSize = 0;
    if (!EVP_EncryptUpdate(ctx, &cipherTextBuf[0], &cipherTextSize, &plainText[0], plainText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encrypt error");
    }

    int lastPartLen = 0;
    if (!EVP_EncryptFinal_ex(ctx, &cipherTextBuf[0] + cipherTextSize, &lastPartLen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptFinal error");
    }
    cipherTextSize += lastPartLen;
    cipherTextBuf.erase(cipherTextBuf.begin() + cipherTextSize, cipherTextBuf.end());

    cipherText.swap(cipherTextBuf);

    EVP_CIPHER_CTX_free(ctx);
}

void Encrypt(const std::string& pathOfPlainText, const std::string& pathOfCipherText)
{
    std::vector<unsigned char> plainText;
    ReadFile(pathOfPlainText, plainText);

    std::vector<unsigned char> hash;
    CalculateHash(plainText, hash);

    std::vector<unsigned char> cipherText;
    EncryptAes(plainText, cipherText);

    WriteFile(pathOfCipherText, cipherText);

    AppendToFile(pathOfCipherText, hash);
}

void DecryptAes(std::vector<unsigned char> chipherText, std::vector<unsigned char>& plainText)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        throw std::runtime_error("DecryptInit error");
    }

    std::vector<unsigned char> decrypredTextBuf(chipherText.size());
    int decrypredTextSize = 0;

    if (!EVP_DecryptUpdate(ctx, &decrypredTextBuf[0], &decrypredTextSize, &chipherText[0], chipherText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptUpdate error");
    }

    int lastPartLen = 0;

    if (!EVP_DecryptFinal_ex(ctx, &decrypredTextBuf[0] + decrypredTextSize, &lastPartLen)) {       
        decryptFinalResults = false;
    }

    else {        
        decryptFinalResults = true;
    }

    decrypredTextSize += lastPartLen;
    decrypredTextBuf.erase(decrypredTextBuf.begin() + decrypredTextSize, decrypredTextBuf.end());

    plainText.swap(decrypredTextBuf);

    EVP_CIPHER_CTX_free(ctx);   
}

bool Decrypt(const std::string& pathOfCipherText, const std::string& pathOfDecrypredText)
{
    std::vector<unsigned char> cipherText;
    ReadFile(pathOfCipherText, cipherText);

    std::vector<unsigned char> hashOfCipherText(cipherText.begin() + cipherText.size() - SHA256_DIGEST_LENGTH, cipherText.end());
    cipherText.resize(cipherText.size() - SHA256_DIGEST_LENGTH);

    std::vector<unsigned char> decrypredText;
    
    DecryptAes(cipherText, decrypredText);

    bool resOfDecrypt = false;

    if (!decryptFinalResults) {
        return resOfDecrypt;
    }

    WriteFile(pathOfDecrypredText, decrypredText);

    std::vector<unsigned char> hashOfDecrypredText;
    CalculateHash(decrypredText, hashOfDecrypredText);

    
    if (hashOfCipherText != hashOfDecrypredText) {
        g_passwordIsNotFound = true;
        resOfDecrypt = false;
    }
    else {
        g_passwordIsNotFound = false;
        resOfDecrypt = true;
    }
    return resOfDecrypt;
}