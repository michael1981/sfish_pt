// PlugSample.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "DicPlug.h"  // 实现 MD5Crack 插件的类

HINSTANCE  g_hInstance = NULL;

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    if(ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        g_hInstance = (HINSTANCE)hModule;  // 保存模块句柄供创建对话框使用
        //InitCommonControls();              // 初始化 Windows 控件
    }

    return TRUE;
}

// MD5Crack4 所需要的导出函数
extern "C" __declspec(dllexport)  IDicPlug*  GetPlugClass(void)
{
    static CDicPlug s_tdic;
    return static_cast<IDicPlug*>(&s_tdic);
}