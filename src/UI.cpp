#include <tchar.h>
#include <cstdio>

#include "UI.h"

#define WIN_WIDTH  64
#define WIN_HEIGHT  128

#define MARGIN_RIGHT 32
#define MARGIN_TOP 32

HWND hwndCurrent;

HBITMAP hBitmapRed;
HBITMAP hBitmapYellow;
HBITMAP hBitmapGreen;
HBITMAP* lphBitmapCurrent;

LRESULT CALLBACK WindowProc(
  _In_ HWND   hwnd,
  _In_ UINT   uMsg,
  _In_ WPARAM wParam,
  _In_ LPARAM lParam
) {
        switch(uMsg)
    {
        case WM_PAINT: {
			PAINTSTRUCT ps;
            HGDIOBJ originalObject;

			HDC hdc = BeginPaint(hwnd, &ps);
			HDC hdc_x = CreateCompatibleDC(NULL);
			HBITMAP hBitmap = *lphBitmapCurrent;
			originalObject = SelectObject(hdc_x, hBitmap); //Put the bitmap into the hdc_x
			
			RECT rect;
			GetWindowRect(hwnd, &rect);
			
			BitBlt(hdc, 0, 0, rect.right - rect.left, WIN_HEIGHT, hdc_x, 0, 0, SRCCOPY); //Draw it.
			
			EndPaint(hwnd, &ps);
            SelectObject(hdc_x, originalObject);
			break;
		}
        case WM_CLOSE:
            DestroyWindow(hwnd);
        break;
        case WM_DESTROY:
            PostQuitMessage(0);
        break;
        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

BOOL initWindow(HINSTANCE hInstance, int nCmdShow) {

    // Load Traffic Light Images
    hBitmapRed = (HBITMAP)LoadImage(NULL, "./images/Red.bmp", IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE); //Load the bitmap
    hBitmapYellow = (HBITMAP)LoadImage(NULL, "./images/Yellow.bmp", IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE); //Load the bitmap
    hBitmapGreen = (HBITMAP)LoadImage(NULL, "./images/Green.bmp", IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE); //Load the bitmap

    lphBitmapCurrent = &hBitmapGreen;


    int horizontal = 0;
    int vertical = 0;
    GetDesktopResolution(horizontal, vertical);
    int X = horizontal - WIN_WIDTH - MARGIN_RIGHT;
    int Y = MARGIN_TOP;



    const TCHAR CLASS_NAME[]  = _T("TrafficLight");

    WNDCLASSEX  wc = { };

    wc.cbSize        = sizeof(WNDCLASSEX);
    wc.style         = 0;
    wc.lpfnWndProc   = WindowProc;
    wc.cbClsExtra    = 0;
    wc.cbWndExtra    = 0;
    wc.hInstance     = hInstance;
    wc.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wc.lpszMenuName  = NULL;
    wc.lpszClassName = CLASS_NAME;
    wc.hIconSm       = LoadIcon(NULL, IDI_APPLICATION);

    if(!RegisterClassEx(&wc)) {
        displayError("RegisterClassEx");
        return FALSE;
    }

    hwndCurrent = CreateWindowEx(
    WS_EX_TOOLWINDOW|WS_EX_TOPMOST,     // Optional window styles.
    CLASS_NAME,                         // Window class
    NULL,                               // Window text
    WS_POPUP | WS_VISIBLE | WS_SYSMENU ,// Window style
    X, Y, WIN_WIDTH, WIN_HEIGHT, // Size and position
    NULL,                               // Parent window    
    NULL,                               // Menu
    hInstance,                          // Instance handle
    NULL                                // Additional application data
    );

    ShowWindow(hwndCurrent, nCmdShow);
    UpdateWindow(hwndCurrent);

    return TRUE;
}

inline void setColor(HBITMAP* hBitmap) {
    lphBitmapCurrent = hBitmap;
    RedrawWindow(hwndCurrent, NULL, NULL, RDW_ERASE|RDW_INVALIDATE);
}

void setRed() {
    setColor(&hBitmapRed);
}

void setYellow() {
    setColor(&hBitmapYellow);
}

void setGreen() {
    setColor(&hBitmapGreen);
}

void displayError(const char *title) {
         char error[16];
        // strcpy("Error: ", error);
        // itoa(GetLastError(), &error[7], 10);
        _stprintf(error, _T("Error: %d"), GetLastError());
        MessageBox(NULL, _T(error), _T(title),
            MB_ICONEXCLAMATION | MB_OK);   
}

void GetDesktopResolution(int& horizontal, int& vertical)
{
   RECT desktop;
   // Get a handle to the desktop window
   const HWND hDesktop = GetDesktopWindow();
   // Get the size of screen to the variable desktop
   GetWindowRect(hDesktop, &desktop);
   // The top left corner will have coordinates (0,0)
   // and the bottom right corner will have coordinates
   // (horizontal, vertical)
   horizontal = desktop.right;
   vertical = desktop.bottom;
}