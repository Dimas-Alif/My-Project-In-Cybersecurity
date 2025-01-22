#include <iostream>
#include <string>
#include <vector>

// Fungsi untuk mencoba semua kombinasi kata sandi
void bruteForcePassword(const std::string& targetPassword, const std::string& characterSet, int maxLength) {
    std::string attempt;

    // Fungsi rekursif untuk menghasilkan kombinasi
    std::function<void(int)> generate = [&](int length) {
        if (length == 0) {
            // Cek jika kombinasi cocok dengan kata sandi
            if (attempt == targetPassword) {
                std::cout << "Password ditemukan: " << attempt << std::endl;
                exit(0); // Keluar jika kata sandi ditemukan
            }
            return;
        }

        // Coba setiap karakter dalam set karakter
        for (char c : characterSet) {
            attempt.push_back(c);
            generate(length - 1);
            attempt.pop_back(); // Hapus karakter terakhir untuk mencoba kombinasi lain
        }
    };

    // Lakukan brute force hingga panjang maksimum
    for (int length = 1; length <= maxLength; ++length) {
        generate(length);
    }

    std::cout << "Password tidak ditemukan dalam panjang maksimum yang diberikan.\n";
}

int main() {
    // Target kata sandi (dalam dunia nyata, ini adalah hash yang ingin kita cocokkan)
    std::string targetPassword = "abc";

    // Karakter yang akan dicoba
    std::string characterSet = "abcdefghijklmnopqrstuvwxyz";

    // Panjang maksimum kata sandi
    int maxLength = 4;

    std::cout << "Mencoba memecahkan password: " << targetPassword << std::endl;
    bruteForcePassword(targetPassword, characterSet, maxLength);

    return 0;
}
