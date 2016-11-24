#include "StdAfx.h"
#include ".\dicplug.h"
#include "resource.h"

CDicPlug::CDicPlug(void)
{
}

CDicPlug::~CDicPlug(void)
{
}

bool  CDicPlug::Initialize(ISetingUI* pSetingUI, 
                 ILogerUI* pLogerUI, ICommandUI* pCommandUI)
{
    // 插件加载后进行初始化
    // 此三个参数暂时不对外开放, 可忽略之
    return true;
}

void  CDicPlug::LanguageChange(const char * newLang, 
                     const char * oldLang)
{
    // 改变界面所使用的语言
}

const char * CDicPlug::GetPlugName(const char* Language)
{
    if(strcmp(Language, "LANG_CN") == 0) // 中文插件名
    {
        return "插件实例代码";
    }
    else // 英文
    {
        return "Plug Sample Code";
    }
}

const char * CDicPlug::GetPlugSID()
{
    // 不可重复的插件 ID, 建议使用 GUID.
    return "F5789CE9-F75A-424b-B5FB-9051FFAD11EE";
}

MD5CRK_HWND  CDicPlug::CreatePlugWindow(MD5CRK_HWND  hWndParent,
                              int x, int y, int cx, int cy, const char* Language)
{
    extern HINSTANCE  g_hInstance;  // DllMain 中保存的

#pragma warning(disable : 4312 4311) // 关闭类型转换警告

    // 创建插件窗口
    return (MD5CRK_HWND)CreateDialog(g_hInstance, 
        MAKEINTRESOURCE(IDD_SETDLG), (HWND)hWndParent, SetDlgProc);

#pragma warning(default : 4312 4311)
}

bool  CDicPlug::AnalyzeCommandLine(const char* cmdline)
{
    // 分析命令行
    return true;
}

bool  CDicPlug::SaveSet(const unsigned char ** outbuf, int * len)
{
    // 保存界面状态
    strcpy((char *)*outbuf, "Hello World");
    *len = 12; // 包含 \0
    return true;
}

bool  CDicPlug::ReadSet(const unsigned char * inbuf, int len)
{
    // 读取界面状态

    // inbuf == "Hello World", len == 12
    return true;
}

bool  CDicPlug::SaveState(const unsigned char ** outbuf, int * len)
{
     // 保存插件状态
    return true;
}

bool  CDicPlug::ReadState(const unsigned char * inbuf, int len)
{
    // 读取插件状态
    return true;
}

void  CDicPlug::ResetPlug(void)
{
    // 重置插件状态
}

bool  CDicPlug::BeginOut(void)
{
    // 开始破解
    return true;
}

int   CDicPlug::FillText(int count, int plain_maxlen,
               unsigned char* plain, int lengths[])
{
    for(int i = 0; i < count; ++i)
    {
        strcpy((char *)&plain[plain_maxlen * i], "plug sample");
        lengths[i] = 11; // 不包含 '\0'
    }

    return count;
}

void  CDicPlug::EndOut(void)
{
    // 停止破解
}

const char * CDicPlug::GetPlugError(void)
{
    return "ERROR_SUCCEED";
}

BOOL APIENTRY CDicPlug::SetDlgProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch(message)
    {
    case WM_INITDIALOG:
        {
            return TRUE;
        }
        break;
    }
    return FALSE;
}
