#pragma once

class ISetingUI;
class ILogerUI;
class ICommandUI;

typedef unsigned int MD5CRK_HWND;

class  IDicPlug
{
public:
    virtual ~IDicPlug() {};

    virtual  bool  Initialize(ISetingUI* pSetingUI, 
                            ILogerUI* pLogerUI, ICommandUI* pCommandUI) = 0;

    virtual  void  LanguageChange(const char * newLang, 
                            const char * oldLang) = 0;

    virtual  const char * GetPlugName(const char* Language) = 0;
    virtual  const char * GetPlugSID() = 0;

    virtual  MD5CRK_HWND  CreatePlugWindow(MD5CRK_HWND  hWndParent,
                            int x, int y, int cx, int cy, const char* Language) = 0;
    virtual  bool  AnalyzeCommandLine(const char* cmdline) = 0;

    virtual  bool  SaveSet(const unsigned char ** outbuf, int * len) = 0;
    virtual  bool  ReadSet(const unsigned char * inbuf, int len) = 0;
    virtual  bool  SaveState(const unsigned char ** outbuf, int * len) = 0;
    virtual  bool  ReadState(const unsigned char * inbuf, int len) = 0;

    virtual  void  ResetPlug(void) = 0;
    virtual  bool  BeginOut(void)  = 0;
    virtual  int   FillText(int count, int plain_maxlen,
                            unsigned char* plain, int lengths[]) = 0;
    virtual  void  EndOut(void)    = 0;

    virtual  const char * GetPlugError(void) = 0;
};