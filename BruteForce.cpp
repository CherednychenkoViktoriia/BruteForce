#include "BruteForce.h"

void BruteForce::ProgressIndicator(std::chrono::duration<double> elapsedTime)
{
    using namespace std::chrono_literals;
    auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>(elapsedTime).count();
    auto elapsedMinutes = std::chrono::duration_cast<std::chrono::minutes>(elapsedTime).count();
    auto speed = m_checkedPasswords / elapsedTime.count();

    std::unique_lock<std::mutex> guard(m_mutex);
    std::cout << m_checkedPasswords << " from " << m_passwordsGenerated << " passwords checked ["
        << m_checkedPasswords * 100 / m_passwordsGenerated << "%]" << std::endl;
    std::cout << "Time elapsed: " << elapsedMinutes % 60 << "m " << elapsedSeconds % 60 << "s" << std::endl;
    std::cout << "Speed: " << speed << " pass/sec" << std::endl;
}

void BruteForce::LogPasswordsChecked(const std::string& pathOfCheckedPasswords, const std::vector<std::string>::iterator& i)
{
    if (g_passwordIsNotFound) {
        std::ofstream fileStream;
        fileStream.open(pathOfCheckedPasswords, std::ios::app);
        fileStream << *i + '\n';
        fileStream.close();
    }
    return;
}

void BruteForce::BruteForcePassword(const std::string& pathOfCipherText, const std::string& pathOfDecrypredText, const std::string& pathOfCheckedPasswords, const std::vector<std::string>::iterator& iterForBeginThread, const std::vector<std::string>::iterator& iterForEndThread)
{
    for (std::vector<std::string>::iterator i = iterForBeginThread; i != iterForEndThread; ++i) {

        PasswordToKey(*i);
        bool res = Decrypt(pathOfCipherText, pathOfDecrypredText);

        if (res) {
            m_foundPassword = *i;
            g_passwordIsNotFound = false;
            break;
        }

        if (m_key == m_passwordLog) {
            LogPasswordsChecked(pathOfCheckedPasswords, i);
        }

        auto end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsedTime = end - m_start;
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(elapsedTime).count();
        if (milliseconds % 100 == 0) {
            ProgressIndicator(elapsedTime);
        }
        ++m_checkedPasswords;
    }
}

void BruteForce::GeneratePasswords()
{
    std::cout << "Passwords generating..." << std::endl;
    const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    int i, j = 0;
    const int maxPasswordLength = 4;
    int guessc[MAX_SIZE] = { 0 };
    char guess[MAX_SIZE + 1] = {};

    for (i = 1; i < MAX_SIZE; guessc[i++] = -1);
    for (i = 1; i <= MAX_SIZE; guess[i++] = '\0');

    while (m_passwordsGenerated++ < pow(sizeof(chars), maxPasswordLength)) {

        i = 0;

        while (guessc[i] == sizeof(chars)) {
            guessc[i] = 0;
            guessc[++i] += 1;
        }

        for (j = 0; j <= i; ++j) {
            if (j < MAX_SIZE) {
                guess[j] = chars[guessc[j]];
            }
        }

        m_vecPassGenerated.emplace_back(guess);
        ++guessc[0];
    }

    std::cout << "Done!" << std::endl;
    std::cout << "Please, enter the key for passwords log: " << std::endl;
    std::cin >> m_key;
    m_start = std::chrono::system_clock::now();
}
