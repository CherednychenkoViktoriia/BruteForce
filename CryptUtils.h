#pragma once

extern bool g_passwordIsNotFound;

void PasswordToKey(std::string& password);

void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash);

void EncryptAes(const std::vector<unsigned char> plainText, std::vector<unsigned char>& cipherText);

void Encrypt(const std::string& pathOfPlainText, const std::string& pathOfCipherText);

void DecryptAes(std::vector<unsigned char> chipherText, std::vector<unsigned char>& plainText);

bool Decrypt(const std::string& pathOfCipherText, const std::string& pathOfDecrypredText);