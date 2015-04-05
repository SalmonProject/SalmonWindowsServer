//Copyright 2015 The Salmon Censorship Circumvention Project
//
//This file is part of the Salmon Server (Windows).
//
//The Salmon Server (Windows) is free software; you can redistribute it and / or
//modify it under the terms of the GNU General Public License as published by
//the Free Software Foundation; either version 3 of the License, or
//(at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//GNU General Public License for more details.
//
//The full text of the license can be found at:
//http://www.gnu.org/licenses/gpl.html

//system tray stuff learned from
//http://www.codeproject.com/Articles/4768/Basic-use-of-Shell-NotifyIcon-in-Win
//thanks Abraxas23!

#include "stdafx.h"
#include <string.h>
#include <stdio.h>
#include "SalmonServerWrapper.h"

//===================================================================
//All globals; see globals.c or .h for full descriptions
#include "globals.h"
//===================================================================

#include "utility.h"

#define MAX_LOADSTRING 100

#define TRAYICONID	1//				ID number for the Notify Icon
#define SWM_TRAYMSG	WM_APP//		the message ID sent to our window

//#define SWM_SHOW	WM_APP + 1//	show the window
//#define SWM_HIDE	WM_APP + 2//	hide the window

#define SWM_HELP	WM_APP + 1//	show help message box
#define SWM_EXIT	WM_APP + 2//	close the window
#define SWM_OFFLINE WM_APP + 3
#define SWM_ONLINE WM_APP + 4

#define IDC_TRAYICON						105
#define IDC_STEALTHDIALOG				106
#define IDI_STEALTHDLG                  107

// Global Variables:
HINSTANCE _win32_Instance;								// current instance
TCHAR _win32_WindowTitle[MAX_LOADSTRING];					// The title bar text
TCHAR _win32_WindowClass[MAX_LOADSTRING];			// the main window class name

NOTIFYICONDATA	_win32_NotifyIconData;	// notify icon data

// Forward declarations of functions included in this code module:
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);

void load_vpncmdexe_Path();
void uninitTLS();
void freeStuff();
void startServer();
void stopServer();

void ensureSalmonConfigDir()
{
	char wholeThing[300];
	sprintf(wholeThing, "%s\\salmon", getenv("APPDATA"));
	WCHAR asWstr[300];
	mbstowcs(asWstr, wholeThing, 300);
	CreateDirectory(asWstr, NULL);
}

int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	//Initialize global strings
	LoadString(hInstance, IDS_APP_TITLE, _win32_WindowTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_SALMONSERVERWRAPPER, _win32_WindowClass, MAX_LOADSTRING);
	//Some Windows voodoo
	WNDCLASSEX wcex;
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WndProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_SALMONSERVERWRAPPER));
	wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = MAKEINTRESOURCE(IDC_SALMONSERVERWRAPPER);
	wcex.lpszClassName = _win32_WindowClass;
	wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));
	RegisterClassEx(&wcex);

	//Perform application initialization:
	if (!InitInstance (hInstance, nCmdShow))
		return FALSE;
	HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_SALMONSERVERWRAPPER));
	MSG msg;


	//Startup logic
	gUsageReportMutex = CreateMutex(NULL, FALSE, NULL);
	load_vpncmdexe_Path();
	ensureSalmonConfigDir();
	startServer();



	//Main message loop:
	while (GetMessage(&msg, NULL, 0, 0))
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}

	if (gServerOnline == SALMON_SERVER_ONLINE)
		stopServer();

	WSACleanup();
	return (int) msg.wParam;
}


//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   _win32_Instance = hInstance; // Store instance handle in our global variable

   hWnd = CreateWindow(_win32_WindowClass, _win32_WindowTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

	if (!hWnd)
		return FALSE;

   // Fill the NOTIFYICONDATA structure and call Shell_NotifyIcon
   ZeroMemory(&_win32_NotifyIconData, sizeof(NOTIFYICONDATA));

	//we're only wanting to support XP and up, so we can just assume it's sizeof(NOTIFYICONDATA)
   _win32_NotifyIconData.cbSize = sizeof(NOTIFYICONDATA);
   //else _win32_NotifyIconData.cbSize = NOTIFYICONDATA_V2_SIZE;

   // the ID number can be anything you choose
   _win32_NotifyIconData.uID = TRAYICONID;

   // state which structure members are valid
   _win32_NotifyIconData.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;

   // load the icon
   _win32_NotifyIconData.hIcon = (HICON)LoadImage(hInstance, MAKEINTRESOURCE(IDI_STEALTHDLG),
	   IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
	   LR_DEFAULTCOLOR);

   // the window to send messages to and the message to send
   //		note:	the message value should be in the
   //				range of WM_APP through 0xBFFF
   _win32_NotifyIconData.hWnd = hWnd;
   _win32_NotifyIconData.uCallbackMessage = SWM_TRAYMSG;

   // tooltip message
   //just a placeholder - startServer() ought to get called soon after this, to fill in a better string.
   wcscpy(_win32_NotifyIconData.szTip, L"Salmon Server: connecting...\nBW target: ? KB/s.");

   Shell_NotifyIcon(NIM_ADD, &_win32_NotifyIconData);

   // free icon handle (NOTE: to keep the icon from going blank (without further intervention) after the user interacts with it, DON'T do this.)
   //if (_win32_NotifyIconData.hIcon && DestroyIcon(_win32_NotifyIconData.hIcon))
	//   _win32_NotifyIconData.hIcon = NULL;

   // call ShowWindow here to make the dialog initially visible
   //ShowWindow(hWnd, nCmdShow);
   //UpdateWindow(hWnd);

   return TRUE;
}


//curBWUsed: int with units of kilobytes / second
void updateTooltip(int curBWUsed, int numUsersConnected)
{
	char tipStrASCII[500];
	WCHAR tipStr[500];


sprintf(tipStrASCII,
"Salmon server: %s\n\
BW target: %sKB/s\n\
Cur BW used: ~%dKB/s\n\
%d %s connected.", 

gServerOnline == SALMON_SERVER_ONLINE ? "online\n" : (gServerOnline == SALMON_SERVER_OFFLINE ? "offline\n" : "connecting\n"),
gOfferedBW ? gOfferedBW : "?",
curBWUsed,
numUsersConnected, numUsersConnected == 1 ? "user" : "users"
);

	mbstowcs(tipStr, tipStrASCII, 128);
	tipStr[127] = 0;

	wcscpy(_win32_NotifyIconData.szTip, tipStr);
	Shell_NotifyIcon(NIM_MODIFY, &_win32_NotifyIconData);
}

void removeIconFromTray()
{
	_win32_NotifyIconData.uFlags = 0;
	Shell_NotifyIcon(NIM_DELETE, &_win32_NotifyIconData);
}

void ShowContextMenu(HWND hWnd)
{
	POINT pt;
	GetCursorPos(&pt);
	HMENU hMenu = CreatePopupMenu();
	if (hMenu)
	{
		if(gServerOnline == SALMON_SERVER_ONLINE)
			InsertMenu(hMenu, -1, MF_BYPOSITION, SWM_OFFLINE, _T("Stop Server"));
		else
			InsertMenu(hMenu, -1, MF_BYPOSITION | (gServerOnline == SALMON_SERVER_OFFLINE ? 0 : MF_GRAYED), SWM_ONLINE, _T("Start Server"));
		//if (IsWindowVisible(hWnd))
		//	InsertMenu(hMenu, -1, MF_BYPOSITION, SWM_HIDE, _T("Hide"));
		//else
		//	InsertMenu(hMenu, -1, MF_BYPOSITION, SWM_SHOW, _T("Show"));
		InsertMenu(hMenu, -1, MF_BYPOSITION, SWM_HELP, _T("Help/About"));
		InsertMenu(hMenu, -1, MF_BYPOSITION, SWM_EXIT, _T("Exit"));

		// note:	must set window to the foreground or the
		//			menu won't disappear when it should
		SetForegroundWindow(hWnd);

		TrackPopupMenu(hMenu, TPM_BOTTOMALIGN, pt.x, pt.y, 0, hWnd, NULL);
		DestroyMenu(hMenu);
	}
}


void helpAboutPopup()
{
MessageBox(NULL,
L"This is the server for the Salmon project (contact: cs-contact-salmon@mx.uillinois.edu). \
It is designed to be run on a volunteer's computer - thanks for being one! It talks to \
Salmon's central directory server, and controls the SoftEther server that should also be \
installed on this computer.\n\n\
Both SoftEther and Salmon run at system startup. If you click 'Stop Server' or exit the \
Salmon server, the SoftEther server will be shut down - although the SoftEther server \
process will remain inactive in the background.\n\n\
To modify the bandwidth you are offering, or to provide different estimates for when your \
server will be online, edit the file:\n\n\
%APPDATA%\\salmon\\salmon_settings\n\n\
See salmon_settings_guide in that same directory for instructions. Stop+start the server \
after modifying your offered bandwidth to make it take effect.\n\n\
This program is licensed under the Free Software Foundation's GPLv3. The source is available \
from our homepage, salmon.cs.illinois.edu.",

L"Salmon Server 1.0", MB_OK);
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND	- process the application menu
//  WM_PAINT	- Paint the main window
//  WM_DESTROY	- post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	PAINTSTRUCT ps;
	HDC hdc;

	switch (message)
	{
	case SWM_TRAYMSG:
		switch (lParam)
		{
		case WM_LBUTTONDBLCLK:
			//ShowWindow(hWnd, SW_RESTORE);
		break;

		case WM_RBUTTONDOWN:
		case WM_CONTEXTMENU:
			ShowContextMenu(hWnd);
		}
	break;

	case WM_SYSCOMMAND:
		if ((wParam & 0xFFF0) == SC_MINIMIZE)
		{
			ShowWindow(hWnd, SW_HIDE);
			return 1;
		}
		else if (wParam == IDM_ABOUT)
			helpAboutPopup(); //DialogBox(_win32_Instance, (LPCTSTR)IDD_ABOUTBOX, hWnd, (DLGPROC)About);
	break;

	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// Parse the menu selections:
		switch (wmId)
		{
		case IDM_ABOUT:
			helpAboutPopup(); //DialogBox(_win32_Instance, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
		break;

		case IDM_EXIT:
			DestroyWindow(hWnd);
		break;

		//case SWM_SHOW:
		//	ShowWindow(hWnd, SW_RESTORE);
		//break;
		//case SWM_HIDE:
		//case IDOK:
		//	ShowWindow(hWnd, SW_HIDE);
		//break;

		case SWM_HELP:
			helpAboutPopup();
		break;

		case SWM_EXIT:
			DestroyWindow(hWnd);
		break;

		case SWM_ONLINE:
			startServer();
		break;

		case SWM_OFFLINE:
			stopServer();
		break;

		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
	break;

	case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		//Add any drawing code here...
		EndPaint(hWnd, &ps);
	break;

	case WM_CLOSE:
		DestroyWindow(hWnd);
	break;

	case WM_DESTROY:
		
		removeIconFromTray();

		if (gServerOnline == SALMON_SERVER_ONLINE)
			stopServer();

		WSACleanup();
		ExitProcess(0);
	break;

	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}

	return 0;
}
