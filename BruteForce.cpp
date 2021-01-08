#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <iostream>

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"

unsigned char key[EVP_MAX_KEY_LENGTH];
unsigned char iv[EVP_MAX_IV_LENGTH];

void ReadFile(const std::string& filePath, std::vector<unsigned char>& buf)
{
    std::basic_fstream<unsigned char> fileStream(filePath, std::ios::binary | std::fstream::in);
    if (!fileStream.is_open())
    {
        throw std::runtime_error("Can not open file " + filePath);
    }

    buf.clear();
    buf.insert(buf.begin(), std::istreambuf_iterator<unsigned char>(fileStream), std::istreambuf_iterator<unsigned char>());

    fileStream.close();
}

void WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf)
{
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary);
    fileStream.write(&buf[0], buf.size());
    fileStream.close();
}

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
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptFinal error");
    }
    decrypredTextSize += lastPartLen;
    decrypredTextBuf.erase(decrypredTextBuf.begin() + decrypredTextSize, decrypredTextBuf.end());

    plainText.swap(decrypredTextBuf);

    EVP_CIPHER_CTX_free(ctx);
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

void Decrypt(const std::string& pathOfChipherText, const std::string& pathOfDecrypredText)
{
    std::vector<unsigned char> chipherText;
    ReadFile(pathOfChipherText, chipherText);

    int hashSize = 64;

    for (unsigned int i = chipherText.size() - hashSize; i < chipherText.size(); ++i) {
        chipherText.pop_back();
    }

    std::vector<unsigned char> hashOfChipherText;
    CalculateHash(chipherText, hashOfChipherText);

    std::vector<unsigned char> decrypredText;
    DecryptAes(chipherText, decrypredText);

    WriteFile(pathOfDecrypredText, decrypredText);

    std::vector<unsigned char> hashOfDecrypredText;
    CalculateHash(chipherText, hashOfDecrypredText);

    if (hashOfChipherText != hashOfDecrypredText) {
        throw std::runtime_error("CompareHashes error");
    }
}

int main(int argc, char** argv)
{
    OpenSSL_add_all_algorithms();
    std::string pass = "pass";
    std::string folderPath = argv[1];
    std::string pathOfChipherText = folderPath + "\\chipher_text";
    std::string pathOfDecrypredText = folderPath + "\\decrypred_text.txt";

    try
    {
        PasswordToKey(pass);
        Decrypt(pathOfChipherText, pathOfDecrypredText);
    }
    catch (const std::runtime_error& ex)
    {
        std::cerr << ex.what();
    }
}