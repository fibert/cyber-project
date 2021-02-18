#include <Windows.h>

#include "UI.h"
#include "agent.h"

constexpr auto LOGIC_SLEEP_INTERVAL = 5000; // 5 Seconds;




int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow)
{
    MSG Msg;
    DWORD prevTickCount = 0;
    DWORD newTickCount = 0;
   
   if (!initWindow(hInstance, nCmdShow)) {
       return -1;
   }

    while(TRUE)
    {
        
        while (PeekMessage(&Msg, NULL, 0, 0, PM_REMOVE) > 0) {

            if (Msg.message == WM_QUIT){
                return Msg.wParam;
            }

            TranslateMessage(&Msg);
            DispatchMessage(&Msg);
        }
        
        newTickCount = GetTickCount();
        if (newTickCount - prevTickCount > LOGIC_SLEEP_INTERVAL) {
            prevTickCount = newTickCount;

            agentMain();
        }

        Sleep(1);
    }
}