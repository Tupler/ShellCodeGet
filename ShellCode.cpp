// Hello.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
//
//@author:tupler
//@desc:GetShellCode
//@date:2022/11/02
//
//
#include <iostream>
#include <Windows.h>
#include <iostream>
#include <Windows.h>


//unicode结构体
typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

// LDR结构体
typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// 其中的一个结构体
typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;


//PEB 
typedef struct __PEB // 65 elements, 0x210 bytes
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB;
// LDR入口
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderModuleList; 
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

void shellcodeBegin() {

    //step.1
    //拿到TEB->PEB->LDR  通过hash寻找到Kernel32.dll基地址
    //
    //
    DWORD base_address = NULL;
    DWORD kernel32_base = 0;
#ifdef _WIN64
//还没写！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！
#else
    base_address = __readfsdword(0x30);
    unsigned short m_counter;
    DWORD ldr_table;
    DWORD dll_name;
    DWORD hash_name;
 
    //通过PEB找到ldr地址
    base_address = (DWORD)((_PEB*)base_address)->pLdr;

    //指向它们各自的双链表中的下一个LDR_MODULE的LIST_ENTRY .Flink代表前一个链表        前一个<->[base_address->InMemoryOrderModuleList]<->   
    //InMemoryOrderModuleList 模块在内存中的顺序
    //_LIST_ENTRY  双链表


    ldr_table = (DWORD)((PPEB_LDR_DATA)base_address)->InLoadOrderModuleList.Flink;//InMemoryOrderModuleList.Flink;
   // printf("%p\n", ldr_table);
    //1. 通过peb里面的LDR找到kernel32的地址
    while (ldr_table) {
        dll_name = (DWORD)((PLDR_DATA_TABLE_ENTRY)ldr_table)->BaseDllName.pBuffer;
        // printf("%x\n", dll_name);

        m_counter = ((PLDR_DATA_TABLE_ENTRY)ldr_table)->BaseDllName.Length;
        //hashname查找
        hash_name = 0;
        do {
            hash_name = _rotr((unsigned long)hash_name, 13);
            if (*((unsigned char*)dll_name) >= 'a')
                hash_name += *((unsigned char*)dll_name) - 0x20;
            else
                hash_name += *((unsigned char*)dll_name);
            dll_name++;
        } while (--m_counter);
        if ((unsigned long)hash_name == 0x6A4ABC5B) {
            //这就是kernel.dll的地址了
            kernel32_base = (DWORD)((PLDR_DATA_TABLE_ENTRY)ldr_table)->DllBase;
            break;
        }
        ldr_table = *(DWORD*)(ldr_table);
        if (kernel32_base != 0) {
            //找到了退出
            break;
        }
    }
    if (kernel32_base == 0) {
    }
#endif 
    
  //step2
    //读取kernel32.dll导出表 寻找 GetProcAddress LoadLibraryA 的偏移  
    // 
    //

     typedef HMODULE(WINAPI* GetProcAddressT)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
    typedef HMODULE(WINAPI* LoadLibraryAT)(_In_ LPCSTR lpLibFileName);
    GetProcAddressT fnGetProcAddress = NULL;

    //导出表
    PIMAGE_NT_HEADERS32 pNtHeaders32 = NULL;
    PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
    // 解析PE头
    pNtHeaders32 = (PIMAGE_NT_HEADERS32)(kernel32_base + ((PIMAGE_DOS_HEADER)kernel32_base)->e_lfanew);
    // 拿到导出表
    pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    // 遍历导出表
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(kernel32_base + pDataDirectory->VirtualAddress);

    DWORD* RVAFunctions = (DWORD*)(kernel32_base + pExportDirectory->AddressOfFunctions);		// VA = 基址 + 导出函数地址表RVA
    DWORD* RVANames = (DWORD*)(kernel32_base + pExportDirectory->AddressOfNames);				// VA = 基址 + 导出函数名称表RVA
    WORD* Ordinals = (WORD*)(kernel32_base + pExportDirectory->AddressOfNameOrdinals);	// VA = 基址 + 导出函数名称序号表
    int numName = pExportDirectory->NumberOfNames;
    char str1[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' };
    int VAFunction, ordinal;
    for (int i = 0; i < numName; i++) {
        DWORD ordinal = *(Ordinals + i);			// 取(序号表+1)的值，即在序号表中找到是第几个作为索引值
        DWORD RVA = *(RVAFunctions + ordinal);	// 在函数地址表中找到对应函数的地址为RVA
        DWORD VAFunction = kernel32_base + RVA;		// 函数绝对地址就是DOS头基地址 + RVA

        RVA = *(RVANames + i);				// 名称地址表中找到索引
        DWORD VA = kernel32_base + RVA;// 绝对地址为DOS头基址+RVA
        char* hashVa = (char*)VA;
        DWORD hash_name = 0;
        //通过hash查找
        while (*hashVa)
        {
            hash_name = (*hashVa++) + (hash_name << 6) + (hash_name << 16) - hash_name;
        }

        hash_name = (hash_name & 0x7FFFFFFF);
        if (hash_name==0xe96588)
        {
            fnGetProcAddress = (GetProcAddressT)VAFunction;
          break;
        }
/*
        //通过逐字比对寻找函数
        if (((char*)VA)[0] == str1[0] &&
            ((char*)VA)[1] == str1[1] &&
            ((char*)VA)[2] == str1[2] &&
            ((char*)VA)[3] == str1[3] &&
            ((char*)VA)[4] == str1[4] &&
            ((char*)VA)[5] == str1[5] &&
            ((char*)VA)[6] == str1[6] &&
            ((char*)VA)[7] == str1[7] &&
            ((char*)VA)[8] == str1[8] &&
            ((char*)VA)[9] == str1[9] &&
            ((char*)VA)[10] == str1[10] &&
            ((char*)VA)[11] == str1[11] &&
            ((char*)VA)[12] == str1[12] &&
            ((char*)VA)[13] == str1[13]
            )
        {
            fnGetProcAddress = (GetProcAddressT)VAFunction;
            break;

        }*/
    }
///////////////////////////////
/**
* Shellcode代码编写地方
*/
    typedef HMODULE(WINAPI* LoadLibraryAT)(_In_ LPCSTR lpLibFileName);
    typedef DWORD(WINAPI* GetModuleFileNameAT)( __in_opt HMODULE hModule,__out_ecount_part(nSize, return +1) LPCH lpFilename,__in     DWORD nSize);
    char kernel32str[] = {'K','E','R','N','E','L','3','2','.','d','l','l','\0'};
    char strLoadLibraryA[] = { 'L','o','a','d','L','i','b','r','a','r','y','A','\0' }; 
    char user32str[] = { 'U','S','E','R','3','2','.','d','l','l','\0' };
    char msgBoxstr[] = { 'M','e','s','s','a','g','e','B','o','x','A','\0' };
    LoadLibraryAT fnLoadlibrary = (LoadLibraryAT)fnGetProcAddress((HMODULE)kernel32_base, strLoadLibraryA);
    typedef int (WINAPI* MessageBoxAT)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);
    MessageBoxAT pMessageBoxA = (MessageBoxAT)fnGetProcAddress(fnLoadlibrary(user32str), msgBoxstr);
    pMessageBoxA(NULL, kernel32str, NULL, NULL); 

}
void shellcodeEnd() {
    
}
int main()
{
   // shellcodeBegin(); test
    puts(" _               _             _    ___   ___  _     ");
    puts("| |_ _   _ _ __ / | ___ _ __  | |_ / _ \\ / _ \\| |___ ");
    puts("| __| | | | '_ \\| |/ _ \\ '__| | __| | | | | | | / __|");
    puts("| |_| |_| | |_) | |  __/ |    | |_| |_| | |_| | \\__ \\");
    puts(" \\__|\\__,_| .__/|_|\\___|_|     \\__|\\___/ \\___/|_|___/");
    puts("          |_|                                        ");
    puts("Your ShellCode in C code");
    puts("char shellcode[]={");
    FILE* fid = fopen("payload.bin", "wb");
    int shellcode_size = (int)shellcodeEnd - (int)shellcodeBegin;
    for (int i = 0; i < shellcode_size; i++)
    {
        
        fwrite(&((unsigned char*)(int)shellcodeBegin)[i], sizeof(char), 1, fid);
        
        if (i== shellcode_size-1) {
            printf("0x%02X", ((unsigned char*)(int)shellcodeBegin)[i]);
        }
        else
        {
            printf("0x%02X,", ((unsigned char*)(int)shellcodeBegin)[i]);
        }
        
    }
    printf("};");
    fclose(fid);
}
