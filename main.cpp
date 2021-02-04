#include <string>
#include <vector>
#include <exception>
#include <iostream>
#include <thread>
#include <future>

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
    obj.GeneratePasswords();

    auto itBeginThread1 = obj.GetVecPassGenerated().begin();
    auto itEndThread1 = std::next(obj.GetVecPassGenerated().begin(), (obj.GetPassGenerated() / 9));
    auto itBeginThread2 = std::next(obj.GetVecPassGenerated().begin(), obj.GetPassGenerated() / 9);
    auto itEndThread2 = std::next(obj.GetVecPassGenerated().begin(), 2 * obj.GetPassGenerated() / 9);
    auto itBeginThread3 = std::next(obj.GetVecPassGenerated().begin(), 2 * obj.GetPassGenerated() / 9);
    auto itEndThread3 = std::next(obj.GetVecPassGenerated().begin(), 3 * obj.GetPassGenerated() / 9);
    auto itBeginThread4 = std::next(obj.GetVecPassGenerated().begin(), 3 * obj.GetPassGenerated() / 9);
    auto itEndThread4 = std::next(obj.GetVecPassGenerated().begin(), 4 * obj.GetPassGenerated() / 9);
    auto itBeginThread5 = std::next(obj.GetVecPassGenerated().begin(), 4 * obj.GetPassGenerated() / 9);
    auto itEndThread5 = std::next(obj.GetVecPassGenerated().begin(), 5 * obj.GetPassGenerated() / 9);
    auto itBeginThread6 = std::next(obj.GetVecPassGenerated().begin(), 5 * obj.GetPassGenerated() / 9);
    auto itEndThread6 = std::next(obj.GetVecPassGenerated().begin(), 6 * obj.GetPassGenerated() / 9);
    auto itBeginThread7 = std::next(obj.GetVecPassGenerated().begin(), 6 * obj.GetPassGenerated() / 9);
    auto itEndThread7 = std::next(obj.GetVecPassGenerated().begin(), 7 * obj.GetPassGenerated() / 9);
    auto itBeginThread8 = std::next(obj.GetVecPassGenerated().begin(), 7 * obj.GetPassGenerated() / 9);
    auto itEndThread8 = std::next(obj.GetVecPassGenerated().begin(), 8 * obj.GetPassGenerated() / 9);
    auto itBeginThread9 = std::next(obj.GetVecPassGenerated().begin(), 8 * obj.GetPassGenerated() / 9);
    auto itEndThread9 = obj.GetVecPassGenerated().end();

    try
    {
        //PasswordToKey(pass);
        //Encrypt(pathOfPlainText, pathOfCipherText);
                  
        std::thread threadForCheckingPasswords1(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), itBeginThread1, itEndThread1);
        std::thread threadForCheckingPasswords2(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), itBeginThread2, itEndThread2);
        std::thread threadForCheckingPasswords3(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), itBeginThread3, itEndThread3);
        std::thread threadForCheckingPasswords4(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), itBeginThread4, itEndThread4);
        std::thread threadForCheckingPasswords5(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), itBeginThread5, itEndThread5);
        std::thread threadForCheckingPasswords6(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), itBeginThread6, itEndThread6);
        std::thread threadForCheckingPasswords7(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), itBeginThread7, itEndThread7);
        std::thread threadForCheckingPasswords8(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), itBeginThread8, itEndThread8);
        std::thread threadForCheckingPasswords9(&BruteForce::BruteForcePassword, &obj, std::ref(pathOfCipherText),
            std::ref(pathOfDecrypredText), std::ref(pathOfCheckedPasswords), itBeginThread9, itEndThread9);
        
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