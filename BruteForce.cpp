#include "BruteForce.h"

void BruteForce::ProgressIndicator(std::chrono::duration<double> elapsedTime)
{
    using namespace std::chrono_literals;
    auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>(elapsedTime).count();
    auto elapsedMinutes = std::chrono::duration_cast<std::chrono::minutes>(elapsedTime).count();
    auto speed = m_checkedPasswords / elapsedTime.count();
   
    std::unique_lock<std::mutex> guard(m_mutex1);
    std::cout << m_checkedPasswords << " from " << m_passwordsGenerated << " passwords checked ["
        << m_checkedPasswords * 100 / m_passwordsGenerated << "%]" << std::endl;
    std::cout << "Time elapsed: " << elapsedMinutes % 60 << "m " << elapsedSeconds % 60 << "s" << std::endl;
    std::cout << "Speed: " << speed << " pass/sec" << std::endl;    
}

void BruteForce::LogPasswordsChecked(const std::string& pathOfCheckedPasswords, const std::vector<std::string>::iterator& i)
{
    std::ofstream fileStream;
    fileStream.open(pathOfCheckedPasswords, std::ios::app);
    fileStream << *i + '\n';
    fileStream.close();    
}

void BruteForce::BruteForcePassword(const std::string& pathOfCipherText, const std::string& pathOfDecrypredText,
    const std::string& pathOfCheckedPasswords, int begin, int end)
{       
    std::vector<std::string> vec;
    vec.reserve(end - begin + 1);

    for (int32_t i = begin; i < end; ++i) {
        char converted[5] = {};
        _itoa_s(i, converted, 36);
        vec.emplace_back(converted);
        ++m_passwordsGenerated;
    }

    for (std::vector<std::string>::iterator i = vec.begin(); i != vec.end() && g_passwordIsNotFound; ++i) {

        PasswordToKey(*i);
        bool res = Decrypt(pathOfCipherText, pathOfDecrypredText);

        if (res) {
            std::unique_lock<std::mutex> guard(m_mutex2);
            m_foundPassword = *i;
            g_passwordIsNotFound = false;
            break;
        }

        if (m_key == m_passwordLog && g_passwordIsNotFound) {
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

const std::string& BruteForce::GetFoundPassword() {
    return m_foundPassword;
}

void BruteForce::SetKey(const std::string& key) {
    m_key = key;
}

void BruteForce::SetStart(const std::chrono::system_clock::time_point& start) {
    m_start = start;
}
