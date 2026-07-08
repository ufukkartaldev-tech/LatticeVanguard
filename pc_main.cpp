/*
  PQC TEST RUNNER FOR PC (Visual Studio / GCC)
  -------------------------------------------
  Bu dosya, ESP32 kodlarını bilgisayarda simüle etmek ve testleri 
  hızlıca koşturmak için eklenmiştir.
*/

#ifndef ARDUINO

#include "src/tests/test_suite.h"
#include <iostream>

int main() {
    std::cout << "===== PQC TEST RUNNER (PC SIMULATION) =====" << std::endl;
    
    // Testleri Başlat
    PQC::Test::TestSuite::run_all_tests();
    
    std::cout << "Devam etmek icin bir tusa basin..." << std::endl;
    getchar();
    
    return 0;
}

#endif
