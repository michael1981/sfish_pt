#pragma once
#include "../public/IDicPlug.h"  // 定义插件接口的 SDK 头文件
#include <Windows.h>

class CDicPlug : public IDicPlug
{
public:
    CDicPlug(void);
    virtual ~CDicPlug(void);

    // 必须的接口
    virtual  bool  Initialize(ISetingUI* pSetingUI, 
        ILogerUI* pLogerUI, ICommandUI* pCommandUI);

    virtual  void  LanguageChange(const char * newLang, 
        const char * oldLang);

    virtual  const char * GetPlugName(const char* Language);
    virtual  const char * GetPlugSID();

    virtual  MD5CRK_HWND  CreatePlugWindow(MD5CRK_HWND  hWndParent,
        int x, int y, int cx, int cy, const char* Language);
    virtual  bool  AnalyzeCommandLine(const char* cmdline);

    virtual  bool  SaveSet(const unsigned char ** outbuf, int * len);
    virtual  bool  ReadSet(const unsigned char * inbuf, int len);
    virtual  bool  SaveState(const unsigned char ** outbuf, int * len);
    virtual  bool  ReadState(const unsigned char * inbuf, int len);

    virtual  void  ResetPlug(void);
    virtual  bool  BeginOut(void);
    virtual  int   FillText(int count, int plain_maxlen,
        unsigned char* plain, int lengths[]);
    virtual  void  EndOut(void);

    virtual  const char * GetPlugError(void);

private:
    // 对话框处理
    static BOOL APIENTRY SetDlgProc(HWND, UINT, WPARAM, LPARAM);

    // your code
};
