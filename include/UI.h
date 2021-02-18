#pragma once
#include <Windows.h>
BOOL initWindow(HINSTANCE, int);

void setRed();
void setYellow();
void setGreen();

void displayError(const char *);
void GetDesktopResolution(int&, int&);
