#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>

// Fungsi untuk mencoba semua kombinasi password secara efisien
void bruteForcePassword(const std::string& targetPassword, const std::string& characterSet, int maxLength) {
    std::string attempt;
    auto startTime = std::chrono::high_resolution_clock::now(); // Catat waktu mulai

    // Fungsi rekursif untuk menghasilkan kombinasi
    std::function<void(int)> generate = [&](int length) {
        if (length == 0) {
            // Cek jika kombinasi cocok dengan kata sandi
            if (attempt == targetPassword) {
                auto endTime = std::chrono::high_resolution_clock::now(); // Catat waktu selesai
                double elapsedTime = std::chrono::duration<double>(endTime - startTime).count();

                std::cout << "\nPassword ditemukan: " << attempt << std::endl;
                std::cout << "Waktu yang diperlukan: " << elapsedTime << " detik" << std::endl;
                exit(0); // Keluar jika kata sandi ditemukan
            }
            return;
        }

        // Coba setiap karakter dalam set karakter
        for (char c : characterSet) {
            attempt.push_back(c);    // Tambahkan karakter
            generate(length - 1);   // Lanjutkan ke tingkat berikutnya
            attempt.pop_back();     // Hapus karakter terakhir untuk mencoba kombinasi lain
        }
    };

    // Lakukan brute force hingga panjang maksimum
    for (int length = 1; length <= maxLength; ++length) {
        std::cout << "Mencoba kombinasi panjang: " << length << std::endl;
        generate(length);
    }

    // Jika tidak ditemukan
    std::cout << "Password tidak ditemukan dalam panjang maksimum yang diberikan.\n";
}

int main() {
    // Target kata sandi (di dunia nyata, ini adalah hash yang harus dicocokkan)
    std::string targetPassword = "Ab#1";

    // Set karakter yang digunakan (huruf besar, kecil, angka, simbol)
    std::string characterSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";

    // Panjang maksimum password
    int maxLength = 5;

    std::cout << "Mencoba memecahkan password: " << targetPassword << "\n";
    bruteForcePassword(targetPassword, characterSet, maxLength);

    return 0;
}
