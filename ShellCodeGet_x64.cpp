#include <iostream>
#include <windows.h>

#include <winternl.h>

typedef struct A_PEB_LDR_DATA
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
    struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
    struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
    VOID* EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    VOID* ShutdownThreadId;                                                 //0x50
} *P_PEB_LDR_DATA ;
//0x138 bytes (sizeof)
typedef struct A_LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    union
    {
        UCHAR FlagGroup[4];                                                 //0x68
        ULONG Flags;                                                        //0x68
        struct
        {
            ULONG PackagedBinary:1;                                         //0x68
            ULONG MarkedForRemoval:1;                                       //0x68
            ULONG ImageDll:1;                                               //0x68
            ULONG LoadNotificationsSent:1;                                  //0x68
            ULONG TelemetryEntryProcessed:1;                                //0x68
            ULONG ProcessStaticImport:1;                                    //0x68
            ULONG InLegacyLists:1;                                          //0x68
            ULONG InIndexes:1;                                              //0x68
            ULONG ShimDll:1;                                                //0x68
            ULONG InExceptionTable:1;                                       //0x68
            ULONG ReservedFlags1:2;                                         //0x68
            ULONG LoadInProgress:1;                                         //0x68
            ULONG LoadConfigProcessed:1;                                    //0x68
            ULONG EntryProcessed:1;                                         //0x68
            ULONG ProtectDelayLoad:1;                                       //0x68
            ULONG ReservedFlags3:2;                                         //0x68
            ULONG DontCallForThreads:1;                                     //0x68
            ULONG ProcessAttachCalled:1;                                    //0x68
            ULONG ProcessAttachFailed:1;                                    //0x68
            ULONG CorDeferredValidate:1;                                    //0x68
            ULONG CorImage:1;                                               //0x68
            ULONG DontRelocate:1;                                           //0x68
            ULONG CorILOnly:1;                                              //0x68
            ULONG ChpeImage:1;                                              //0x68
            ULONG ChpeEmulatorImage:1;                                      //0x68
            ULONG ReservedFlags5:1;                                         //0x68
            ULONG Redirected:1;                                             //0x68
            ULONG ReservedFlags6:2;                                         //0x68
            ULONG CompatDatabaseProcessed:1;                                //0x68
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    BYTE Reserved1[48];
    // struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8 18
    // struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    // enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
    DWORD32 Reserved2;
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
    ULONG CheckSum;                                                         //0x120
    VOID* ActivePatchImageBase;                                             //0x128
    ULONG Reserved3;
    // enum _LDR_HOT_PATCH_STATE HotPatchState;                                //0x130
} *PA_LDR_DATA_TABLE_ENTRY; 

void scbegin(){
    // 通过gs寄存器获取PEB
    PPEB ppeb = (PPEB)__readgsqword(0x60);
    
    // 获取LDR链
    P_PEB_LDR_DATA ldr = (P_PEB_LDR_DATA)ppeb->Ldr;
    //开始遍历LIST_ENTRY链
    _LIST_ENTRY x =(_LIST_ENTRY)(ldr->InLoadOrderModuleList);
    PLIST_ENTRY xf = (PLIST_ENTRY)(x.Flink);
    PLIST_ENTRY XfBlink = x.Blink;
    PA_LDR_DATA_TABLE_ENTRY ldrEntry = (PA_LDR_DATA_TABLE_ENTRY)xf;
    PWSTR b =ldrEntry->BaseDllName.Buffer;

    
    ULONG hash_name = 0;
    ULONG64 DllBase =0;
    //通过HASH查找 KERNEL32的baseAddr x64使用ULONG64
    while (XfBlink != xf)
    {
        size_t m_counter = ldrEntry->BaseDllName.Length / 2;
        //printf("len :%d\n",m_counter);
        do {
            hash_name = _rotr((unsigned long)hash_name, 13);
            if (*b >= 'a')
                hash_name += *b - 0x20;
            else
                hash_name += *b;
            //PWSTR 一次+2
            b++;
            
        } while (--m_counter);
        if(hash_name==0x563c38a4){
            DllBase = (ULONG64)ldrEntry->DllBase;
            break;
        }

        xf = xf->Flink;
        ldrEntry = (PA_LDR_DATA_TABLE_ENTRY)xf;
        b =ldrEntry->BaseDllName.Buffer;

    }
    if (DllBase==0)
    {

        return ;
    }
    
    //解析DOS头
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)DllBase;
    //解析PE头
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64) (DllBase + pDosHeader->e_lfanew);
    //解析数据目录中的导出表目录
    PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)&pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    //解析导出表
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(DllBase + pDataDir->VirtualAddress);

   //    RVA + IMAGEBASE  解析导出名称表和名称
   ULONG* pNamesTable =(ULONG*)(DllBase + pExportDir->AddressOfNames);  
   ULONG* pNames = (ULONG*) (DllBase + *pNamesTable);

    size_t i =0;
    //遍历导出函数名称表 hash查找GetProcAddress
    ULONG FunHash;
    while ( i !=pExportDir->NumberOfNames)
    {
        

            FunHash=0;
            PCHAR tempNames = (PCHAR)pNames;
            while(*tempNames != 0 ){
            FunHash = _rotr((unsigned long)FunHash, 13);
            if (*tempNames >= 'a')
                FunHash += *tempNames - 0x20;
            else
                FunHash += *tempNames;
            //PWSTR 一次+2
            tempNames+=1;

            }
            if(FunHash==0x1acaee7a){
               
                break;
            }

        
        i++;
        pNames = (ULONG*) (DllBase + *(pNamesTable++));
    }

    WORD* Odi = (WORD*)(DllBase+pExportDir->AddressOfNameOrdinals);
    
    ULONG* FunAddressTable = (ULONG*)(DllBase + pExportDir->AddressOfFunctions);
    

    typedef FARPROC (WINAPI* MYGetProcAddress) (HMODULE hModule, LPCSTR lpProcName);
    typedef HMODULE (WINAPI* MYLoadLibraryA) (LPCSTR lpLibFileName);
    typedef int (WINAPI *MYMessageBoxA) (HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType);
    ULONG64 dwGetProc =(ULONG64)(DllBase+FunAddressTable[Odi[i]-1]);
    MYGetProcAddress pGetProcAddress = (MYGetProcAddress)dwGetProc;
    char szLoadLibraryA[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    char szUser32[] = {'u','s','e','r','3','2','.','d','l','l',0};
    char szMessageBOX[] = {'M','e','s','s','a','g','e','B','o','x','A',0};
    MYLoadLibraryA pLoadLibraryA = (MYLoadLibraryA)pGetProcAddress((HMODULE)DllBase,szLoadLibraryA);
    HMODULE pUser32 = pLoadLibraryA(szUser32);
    MYMessageBoxA pMessageBoxA = (MYMessageBoxA)pGetProcAddress(pUser32,szMessageBOX);

    pMessageBoxA(0,0,0,0);
}

void scEnd(){

}
int main(){
    puts(" _               _             _    ___   ___  _     ");
    puts("| |_ _   _ _ __ / | ___ _ __  | |_ / _ \\ / _ \\| |___ ");
    puts("| __| | | | '_ \\| |/ _ \\ '__| | __| | | | | | | / __|");
    puts("| |_| |_| | |_) | |  __/ |    | |_| |_| | |_| | \\__ \\");
    puts(" \\__|\\__,_| .__/|_|\\___|_|     \\__|\\___/ \\___/|_|___/");
    puts("          |_|                                        ");
    puts("Version:x64");
    puts("Your ShellCode in C code");
    size_t scLen = (ULONG64)scEnd - (ULONG64)scbegin;
    printf_s("unsigned char buf[%d]={", scLen);
    for (size_t i = 0; i < scLen; i++)
    {

        if (i== scLen-1) {
            printf("0x%02x", (((unsigned char*)scbegin)[i]));
        }
        else
        {
            printf("0x%02x,", (((unsigned char*)scbegin)[i]));
        }
        
    }
    printf("};");
    return 0;
}