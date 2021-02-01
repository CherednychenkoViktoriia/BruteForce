#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <iostream>
#include <chrono>
#include <math.h>
#include <thread>
#include <mutex>

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"

unsigned char key[EVP_MAX_KEY_LENGTH];
unsigned char iv[EVP_MAX_IV_LENGTH];
bool g_passwordIsNotFound = true;
bool g_decryptFinalResults = true;
std::atomic<unsigned int> g_checkedPasswords = 0;
std::mutex mutex;

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

void AppendToFile(const std::string& filePath, const std::vector<unsigned char>& buf)
{
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary | std::ios::app);
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
        g_decryptFinalResults = false;        
    }

    else {
        g_decryptFinalResults = true;
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

    if (!g_decryptFinalResults) {
        return false;
    }

    WriteFile(pathOfDecrypredText, decrypredText);

    std::vector<unsigned char> hashOfDecrypredText;
    CalculateHash(decrypredText, hashOfDecrypredText);

    bool res = false;

    if (hashOfCipherText != hashOfDecrypredText) {
        g_passwordIsNotFound = true;
        res = false;        
    }
    else {
        g_passwordIsNotFound = false;
        res = true;
    }    
    return res;
}

void ProgressIndicator(unsigned int passwordsGenerated, std::chrono::duration<double> elapsedTime)
{        
    using namespace std::chrono_literals;
    auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>(elapsedTime).count();
    auto elapsedMinutes = std::chrono::duration_cast<std::chrono::minutes>(elapsedTime).count();
    auto speed = g_checkedPasswords / elapsedTime.count();
   
    std::cout << g_checkedPasswords << " from " << passwordsGenerated << " passwords checked ["
        << g_checkedPasswords * 100 / passwordsGenerated << "%]" << std::endl;
    std::cout << "Time elapsed: " << elapsedMinutes % 60 << "m " << elapsedSeconds % 60 << "s" << std::endl;
    std::cout << "Speed: " << speed << " pass/sec" << std::endl;    
}

void LogPasswordsChecked(const std::string& pathOfCheckedPasswords, std::vector<std::string>& vectorPasswordsGenerated)
{    
    std::fstream fileStream;
    fileStream.open(pathOfCheckedPasswords, std::fstream::app);   
    fileStream << vectorPasswordsGenerated[g_checkedPasswords] + '\n';
    fileStream.close();     
}

void BruteForce(std::vector<std::string>& vectorPasswordsGenerated, const std::string& pathOfCipherText,
    const std::string& pathOfDecrypredText, std::chrono::system_clock::time_point start, unsigned int passwordsGenerated,
    const std::string& pathOfCheckedPasswords, std::string& passwordLog, std::string& key)
{   
    std::unique_lock<std::mutex> guard(mutex);

    for (; g_checkedPasswords < passwordsGenerated && g_passwordIsNotFound; ++g_checkedPasswords) {

        PasswordToKey(vectorPasswordsGenerated[g_checkedPasswords]);
        bool res = Decrypt(pathOfCipherText, pathOfDecrypredText);

        if (key == passwordLog) {
            LogPasswordsChecked(pathOfCheckedPasswords, vectorPasswordsGenerated);
        }

        if (res) {
            std::cout << vectorPasswordsGenerated[g_checkedPasswords] << std::endl;
            g_passwordIsNotFound = false;
            break;
        }        

        auto end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsedTime = end - start;
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(elapsedTime).count();
        if (milliseconds % 100 == 0) {
            ProgressIndicator(passwordsGenerated, elapsedTime);
        }
    }
}

void CheckPassword(const std::string& pathOfCheckedPasswords, const std::string& pathOfCipherText, const std::string& pathOfDecrypredText)
{            
    std::cout << "Passwords generating..." << std::endl;
    const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    int i, j = 0;
    const int maxSize = 5;
    const int maxPasswordLength = 4;
    int guessc[maxSize] = { 0 };     
    char guess[maxSize + 1] = {};
        
    for (i = 1; i < maxSize; guessc[i++] = -1);        
    for (i = 1; i <= maxSize; guess[i++] = '\0');      
          
    unsigned int passwordsGenerated = 0;
    std::vector<std::string> vectorPasswordsGenerated;

    std::chrono::system_clock::time_point start = std::chrono::system_clock::now();

    while(passwordsGenerated++ < pow(sizeof(chars), maxPasswordLength)) {

        if (!g_passwordIsNotFound) {
            break;
        }

        i = 0;

        while (guessc[i] == sizeof(chars)) {
            guessc[i] = 0;               
            guessc[++i] += 1;             
        }

        for (j = 0; j <= i; ++j) {         
            if (j < maxSize) {
                guess[j] = chars[guessc[j]];
            }
        }            
            
        vectorPasswordsGenerated.emplace_back(guess);        
        ++guessc[0];                   
    } 

    std::cout << "Done!" << std::endl;
    std::cout << "Please, enter the key for passwords log: " << std::endl;
    std::string key;
    std::cin >> key;
    std::string passwordLog = "--log_passwords";

    for (unsigned int i = 0; i < passwordsGenerated && g_passwordIsNotFound; ++i) {
    
        std::thread threadForCheckingPasswords1(BruteForce, std::ref(vectorPasswordsGenerated), std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), start, passwordsGenerated, std::ref(pathOfCheckedPasswords), std::ref(passwordLog), std::ref(key));
        std::thread threadForCheckingPasswords2(BruteForce, std::ref(vectorPasswordsGenerated), std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), start, passwordsGenerated, std::ref(pathOfCheckedPasswords), std::ref(passwordLog), std::ref(key));
        std::thread threadForCheckingPasswords3(BruteForce, std::ref(vectorPasswordsGenerated), std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), start, passwordsGenerated, std::ref(pathOfCheckedPasswords), std::ref(passwordLog), std::ref(key));
        std::thread threadForCheckingPasswords4(BruteForce, std::ref(vectorPasswordsGenerated), std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), start, passwordsGenerated, std::ref(pathOfCheckedPasswords), std::ref(passwordLog), std::ref(key));
        std::thread threadForCheckingPasswords5(BruteForce, std::ref(vectorPasswordsGenerated), std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), start, passwordsGenerated, std::ref(pathOfCheckedPasswords), std::ref(passwordLog), std::ref(key));
        std::thread threadForCheckingPasswords6(BruteForce, std::ref(vectorPasswordsGenerated), std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), start, passwordsGenerated, std::ref(pathOfCheckedPasswords), std::ref(passwordLog), std::ref(key));
                                  
        threadForCheckingPasswords1.join();
        threadForCheckingPasswords2.join();
        threadForCheckingPasswords3.join();
        threadForCheckingPasswords4.join();
        threadForCheckingPasswords5.join();
        threadForCheckingPasswords6.join();       
    }
}

int main(int argc, char** argv)
{  
    OpenSSL_add_all_algorithms();
    //std::string pass = "pass";   
    std::string folderPath = argv[1];
    std::string pathOfPlainText = folderPath + "\\plain_text.txt";
    std::string pathOfCipherText = folderPath + "\\chipher_text_brute_force";
    std::string pathOfDecrypredText = folderPath + "\\decrypred_text.txt";
    std::string pathOfCheckedPasswords = folderPath + "\\checked_passwords.txt";

    try
    {
        //PasswordToKey(pass);
        //Encrypt(pathOfPlainText, pathOfCipherText);
        CheckPassword(pathOfCheckedPasswords, pathOfCipherText, pathOfDecrypredText);
        //Decrypt(pathOfCipherText, pathOfDecrypredText);
    }
    catch (const std::runtime_error& ex)
    {
        std::cerr << ex.what();
    }
}