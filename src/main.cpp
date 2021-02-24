#include <Windows.h>

#include "UI.h"
#include "agent.h"

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_INFO
#include "spdlog/spdlog.h"
#include "spdlog/sinks/rotating_file_sink.h"

void initLogger() {
    try
    {
        auto file_logger = spdlog::rotating_logger_mt("file_logger", "log.txt", 1024 * 1024 * 5, 3);
        spdlog::set_default_logger(file_logger);
        spdlog::set_pattern("[%Y-%m-%d %T] [%l] %v");
        spdlog::flush_on(spdlog::level::info);
    }
    catch (const spdlog::spdlog_ex& ex)
    {
        OutputDebugStringA("Log init failed");
    }
}


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

   initLogger();

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