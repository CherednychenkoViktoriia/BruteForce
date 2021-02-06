#include <string>
#include <vector>
#include <exception>
#include <iostream>
#include <thread>

#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/sha.h"

#include "FsUtils.h"
#include "CryptUtils.h"
#include "BruteForce.h"

int main(int argc, char** argv)
{  
    OpenSSL_add_all_algorithms();
    //std::string pass = "pass";   
    std::string folderPath = argv[1];
    std::string pathOfPlainText = folderPath + "\\plain_text.txt";
    std::string pathOfCipherText = folderPath + "\\chipher_text_brute_force";
    std::string pathOfDecrypredText = folderPath + "\\decrypred_text.txt";
    std::string pathOfCheckedPasswords = folderPath + "\\checked_passwords.txt";

    BruteForce obj;    
  
    try
    {   //PasswordToKey(pass);
        //Encrypt(pathOfPlainText, pathOfCipherText);

        std::chrono::system_clock::time_point start = std::chrono::system_clock::now();
        obj.SetStart(start);

        std::cout << "Please, enter the key for passwords log: " << std::endl;
        std::string key;
        std::cin >> key;
        obj.SetKey(key);          

        std::thread threadForCheckingPasswords1(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), 0, 36 * 36 * 36 * 4);
        std::thread threadForCheckingPasswords2(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), 36 * 36 * 36 * 4, 36 * 36 * 36 * 8);
        std::thread threadForCheckingPasswords3(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), 36 * 36 * 36 * 8, 36 * 36 * 36 * 12);
        std::thread threadForCheckingPasswords4(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), 36 * 36 * 36 * 12, 36 * 36 * 36 * 16);
        std::thread threadForCheckingPasswords5(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), 36 * 36 * 36 * 16, 36 * 36 * 36 * 20);
        std::thread threadForCheckingPasswords6(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), 36 * 36 * 36 * 20, 36 * 36 * 36 * 24);
        std::thread threadForCheckingPasswords7(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), 36 * 36 * 36 * 24, 36 * 36 * 36 * 28);
        std::thread threadForCheckingPasswords8(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), 36 * 36 * 36 * 28, 36 * 36 * 36 * 32);
        std::thread threadForCheckingPasswords9(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), 36 * 36 * 36 * 32, 36 * 36 * 36 * 36);
        
        threadForCheckingPasswords1.join();
        threadForCheckingPasswords2.join();
        threadForCheckingPasswords3.join();
        threadForCheckingPasswords4.join();
        threadForCheckingPasswords5.join();
        threadForCheckingPasswords6.join();
        threadForCheckingPasswords7.join();
        threadForCheckingPasswords8.join();
        threadForCheckingPasswords9.join();
        
        std::ofstream fileStream;
        fileStream.open(pathOfCheckedPasswords, std::ios::app);
        fileStream << obj.GetFoundPassword() + '\n';
        fileStream.close();
        std::cout << "Password is: " << obj.GetFoundPassword() << std::endl;
       
        //Decrypt(pathOfCipherText, pathOfDecrypredText);
    }
    catch (const std::runtime_error& ex)
    {
        std::cerr << ex.what();
    }
}