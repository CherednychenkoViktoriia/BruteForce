#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <iostream>
#include <chrono>
#include <math.h>
#include <mutex>

#include "FsUtils.h"
#include "CryptUtils.h"

#define MAX_SIZE 5  

class BruteForce
{
public:
    BruteForce() {}

    ~BruteForce() {}

    void ProgressIndicator(std::chrono::duration<double> elapsedTime);

    void LogPasswordsChecked(const std::string& pathOfCheckedPasswords, const std::vector<std::string>::iterator& i);

    void BruteForcePassword(const std::string& pathOfCipherText, const std::string& pathOfDecrypredText,
        const std::string& pathOfCheckedPasswords, int begin, int end);       
    
    const std::string& GetFoundPassword();

    void SetKey(const std::string& key);

    void SetStart(const std::chrono::system_clock::time_point& start);

private:    
    std::atomic<uint32_t> m_passwordsGenerated = 0;
    std::atomic<uint32_t> m_checkedPasswords = 0;    
    std::string m_key;
    std::string m_passwordLog = "--log_passwords";
    std::chrono::system_clock::time_point m_start;
    std::mutex m_mutex1;    
    std::mutex m_mutex2;
    std::string m_foundPassword;        
};