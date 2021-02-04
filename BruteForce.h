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
        const std::string& pathOfCheckedPasswords, const std::vector<std::string>::iterator& iterForBeginThread,
        const std::vector<std::string>::iterator& iterForEndThread);

    void GeneratePasswords();
    
    uint32_t GetPassGenerated() const {
        return m_passwordsGenerated;
    }   

    std::vector<std::string>& GetVecPassGenerated() {
        return m_vecPassGenerated;
    }

    const std::string& GetFoundPassword() {
        return m_foundPassword;
    }

private:
    std::vector<std::string> m_vecPassGenerated;
    uint32_t m_passwordsGenerated = 0;
    std::atomic<uint32_t> m_checkedPasswords = 0;    
    std::string m_key;
    std::string m_passwordLog = "--log_passwords";
    std::chrono::system_clock::time_point m_start;
    std::mutex m_mutex;    
    std::string m_foundPassword;
};