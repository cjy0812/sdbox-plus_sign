#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <iostream>
#include <string>
#include <io.h>
#include <fcntl.h>
 
 
// 获取指定进程的所有线程ID
std::vector<DWORD> GetProcessThreads(DWORD processId) {
    std::vector<DWORD> threadIds;
 
    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
 
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcout << L"创建快照失败!" << std::endl;
        return threadIds;
    }
 
    // 枚举线程
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == processId) {
                threadIds.push_back(te.th32ThreadID);
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
    return threadIds;
}
 
// 挂起进程的所有线程
bool SuspendProcess(DWORD processId) {
    std::vector<DWORD> threadIds = GetProcessThreads(processId);
    for (DWORD threadId : threadIds) {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (hThread != NULL) {
            DWORD suspendCount = SuspendThread(hThread);
            if (suspendCount == (DWORD)-1) {
                std::wcout << L"[i] 进程挂起，线程ID: " << threadId << std::endl;
            }
            CloseHandle(hThread);
        }
        else {
            std::wcout << L"[i] 无法打开线程，线程ID: " << threadId << std::endl;
        }
    }
    return true;
}
 
// 恢复进程的所有线程
bool ResumeProcess(DWORD processId) {
    std::vector<DWORD> threadIds = GetProcessThreads(processId);
    for (DWORD threadId : threadIds) {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (hThread != NULL) {
            DWORD resumeCount = ResumeThread(hThread);
            if (resumeCount == (DWORD)-1) {
                std::wcout << L"[i] 恢复进程挂起状态，线程ID: " << threadId << std::endl;
            }
            CloseHandle(hThread);
        }
        else {
            std::wcout << L"[x] 恢复进程挂起失败: " << threadId << std::endl;
        }
    }
    return true;
}
 
// 获取指定进程的句柄
HANDLE GetProcessHandle(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return NULL;
 
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (!processName.compare(pe.szExeFile)) {
                CloseHandle(hSnapshot);
                return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
 
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return NULL;
}
 
// 在进程内存中搜索字节模式
std::vector<uintptr_t> SearchMemory(HANDLE hProcess, const std::vector<uint8_t>& pattern) {
    std::vector<uintptr_t> results;
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t address = 0;
 
    while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ))) {
 
            std::vector<uint8_t> buffer(mbi.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer.data(), mbi.RegionSize, &bytesRead)) {
                for (size_t i = 0; i < bytesRead - pattern.size(); ++i) {
 
                    if (memcmp(buffer.data() + i, pattern.data(), pattern.size()) == 0) {
                        results.push_back(address + i);
                    }
                }
            }
        }
        address += mbi.RegionSize;
    }
    return results;
}
 
bool WriteMemory(HANDLE hProcess, uintptr_t address, const std::vector<uint8_t>& newData) {
    DWORD oldProtect;
    // 改变内存区域的保护为可写
    if (!VirtualProtectEx(hProcess, (LPVOID)address, newData.size(), PAGE_READWRITE, &oldProtect)) {
        return false;
    }
 
    SIZE_T bytesWritten;
    if (WriteProcessMemory(hProcess, (LPVOID)address, newData.data(), newData.size(), &bytesWritten)) {
        // 恢复原来的内存保护
        VirtualProtectEx(hProcess, (LPVOID)address, newData.size(), oldProtect, &oldProtect);
        return bytesWritten == newData.size();
    }
 
    // 恢复原来的内存保护
    VirtualProtectEx(hProcess, (LPVOID)address, newData.size(), oldProtect, &oldProtect);
    return false;
}
 
bool EnablePrivilege(LPCWSTR priv) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
 
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
 
    if (!LookupPrivilegeValueW(NULL, priv, &luid)) {
        CloseHandle(hToken);
        return false;
    }
 
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
 
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }
 
    CloseHandle(hToken);
    return true;
}
 
 
 
bool TerminateProcessByName(const std::wstring& processName) {
    // 获取进程快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcout << L"[x] 无法获取进程快照" << std::endl;
        return false;
    }
 
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
 
    // 遍历进程列表
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // 如果进程名称匹配
            if (processName == pe32.szExeFile) {
                // 打开进程
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                if (hProcess != NULL) {
                    // 终止进程
                    BOOL result = TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                    if (result) {
                        std::wcout << L"[v] " << processName << L"已经被结束" << std::endl;
                        CloseHandle(hSnapshot);
                        return true;
                    }
                    else {
                        std::wcout << L"[x] 无法结束进程" << std::endl;
                        CloseHandle(hSnapshot);
                        return false;
                    }
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
 
    std::wcout << L"[x] 未找到进程" << std::endl;
    CloseHandle(hSnapshot);
    return false;
}
bool StartProcessWithArgs(const std::wstring& exePath, const std::wstring& args) {
    // 创建 STARTUPINFO 结构体，初始化为零
    STARTUPINFO si = { 0 };
    si.cb = sizeof(STARTUPINFO);
 
    // 创建 PROCESS_INFORMATION 结构体，初始化为零
    PROCESS_INFORMATION pi = { 0 };
 
    // 构造命令行
    std::wstring commandLine = exePath + L" " + args;
 
    // 使用 CreateProcess 启动进程
    if (CreateProcess(
        nullptr,                 // 应用程序名称，如果命令行中包含程序路径，此参数可以为 nullptr
        &commandLine[0],         // 命令行字符串
        nullptr,                 // 进程安全属性
        nullptr,                 // 线程安全属性
        FALSE,                   // 是否继承句柄
        0,                       // 创建标志
        nullptr,                 // 环境变量
        nullptr,                 // 当前目录
        &si,                     // STARTUPINFO
        &pi                      // PROCESS_INFORMATION
    )) {
        std::wcout << L"[i] 进程创建成功" << std::endl;
        // 等待进程结束
        // WaitForSingleObject(pi.hProcess, INFINITE);
 
        // 关闭进程和线程句柄
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
 
        return true;
    }
    else {
        std::wcout << L"[x] 无法创建进程 错误代码: " << GetLastError() << std::endl;
        return false;
    }
}
 
int setRegister() {
    std::wstring command = L"reg delete \"HKEY_LOCAL_MACHINE\\SECURITY\\SBIE\" /f";
    int result = _wsystem(command.c_str());
    return (result == 0);
  
}
int search() {
 
    std::wstring processName = L"SbieSvc.exe";
    HANDLE hProcess = GetProcessHandle(processName);
    std::wcout << L"[i] 正在打开进程" << std::endl;
    if (!hProcess) {
        std::wcout << L"[x] 无法打开进程: " << processName << std::endl;
        return -1;
    }
    DWORD pid = GetProcessId(hProcess);
 
    SuspendProcess(pid);
 
    std::wcout << L"[i] 正在查找特征字符串" << std::endl;
    // 查找 UTF-8 编码的字符串 "63F49D96BDBA28F8428B4A5008D1A587" 这个就是被封锁的签名
    std::string searchString = "63F49D96BDBA28F8428B4A5008D1A587";
    std::vector<uint8_t> pattern(searchString.begin(), searchString.end());
    std::vector<uintptr_t> addresses = SearchMemory(hProcess, pattern);
    if (addresses.size() == 0) {
        std::wcout << L"[x] 找不到匹配项" << std::endl;
        std::string searchString2 = "ZunMXZunMXZunMXZunMXZunMXZunMX55";
        std::vector<uint8_t> newData(searchString2.begin(), searchString2.end());
        std::vector<uintptr_t> addresses2 = SearchMemory(hProcess, newData);
        if (addresses2.size() > 0) {
            std::wcout << L"[i] 已经替换过了" << std::endl;
            return 0;
        }
        return -1;
    }
    std::string newString = "ZunMXZunMXZunMXZunMXZunMXZunMX55";
    std::vector<uint8_t> newData(newString.begin(), newString.end());
    for (auto addr : addresses) {
        std::wcout << L"[i] 找到匹配项: 0x" << std::hex << addr << std::endl;
        if (WriteMemory(hProcess, addr, newData)) {
            std::wcout << L"[v] 成功写入: 0x" << std::hex << addr << std::endl;
        }
        else {
            std::wcout << L"[x] 写入失败: 0x" << std::hex << addr << std::endl;
        }
    }
    CloseHandle(hProcess);
 
    ResumeProcess(pid);
    return 0;
}
int main() {
    _setmode(_fileno(stdout), _O_U16TEXT); // 启用 wcout Unicode 输出
    // 启用 SeBackupPrivilege 来获取高级权限
    if (!EnablePrivilege(SE_TAKE_OWNERSHIP_NAME)) {
        std::wcout << L"[x] 提权失败" << std::endl;
        return 1;
    }
    if (TerminateProcessByName(L"SbieSvc.exe")) {
        std::wcout << L"[i] 结束进程成功，准备重新启动" << std::endl;
    }
    StartProcessWithArgs(L"KmdUtil.exe", L"start SbieSvc");
    setRegister();
    while (search() == -1) {
        Sleep(1000);
    }
    std::wcout << L"[i] 程序已结束" << std::endl;
    Sleep(3000);
    return 0;
}
