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

#include "stdafx.h"

#include <wincrypt.h>

#include "constants.h"
#include "globals.h"

#include "connect_tls.h"
#include "utility.h"

void stopServer();

//NOTE: yes, this is always the Program Files (NOT x86) directory. softether installs to Program Files (NOT x86) on a 64 bit machine.
//microsoft doesn't want a 32 bit program seeing the "real" Program Files directory on a 64-bit machine, since it would mess with
//the emulation layer that the 32-on-64 thing works on. that doesn't apply to us, though; we're just trying to find vpncmd.exe to system("") it.
void load_vpncmdexe_Path()
{
	WCHAR vpncmdPathW[VPNCMDPATH_BUFSIZE];

	GetSystemWindowsDirectory(vpncmdPathW, 150);
	wcstombs(g_vpncmdPath, vpncmdPathW, 150);
	for (int i = 0; i < strlen(g_vpncmdPath); i++)
		g_vpncmdPath[i] = (char)toupper(g_vpncmdPath[i]);
	char* lastWindows = 0;
	char* lastTemp = strstr(g_vpncmdPath, "WINDOWS");
	while (lastTemp)
	{
		lastWindows = lastTemp;
		lastTemp = strstr(lastTemp+1, "WINDOWS");
	}
	if (lastWindows)
		*lastWindows = '\0';

	char vpnc[VPNCMDPATH_BUFSIZE];
	char vpnc64[VPNCMDPATH_BUFSIZE];

	strcpy(vpnc, g_vpncmdPath);
	strcpy(vpnc64, g_vpncmdPath);
	strcat(vpnc, "Program Files\\SoftEther VPN Server\\vpncmd.exe");
	strcat(vpnc64, "Program Files\\SoftEther VPN Server\\vpncmd_x64.exe");	

	mbstowcs(vpncmdPathW, vpnc64, VPNCMDPATH_BUFSIZE);
	DWORD vpncmdAttributes = GetFileAttributes(vpncmdPathW);
	if (vpncmdAttributes != INVALID_FILE_ATTRIBUTES && !(vpncmdAttributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		strcpy(g_vpncmdPath, vpnc64);
		return;
	}

	mbstowcs(vpncmdPathW, vpnc, VPNCMDPATH_BUFSIZE);
	vpncmdAttributes = GetFileAttributes(vpncmdPathW);
	if (vpncmdAttributes != INVALID_FILE_ATTRIBUTES && !(vpncmdAttributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		strcpy(g_vpncmdPath, vpnc);
		return;
	}
	
	strcpy(g_vpncmdPath, vpnc);
	char vpncmdErrMsg[150 + VPNCMDPATH_BUFSIZE];
	strcpy(vpncmdErrMsg, "The following file (or vpncmd_x64.exe, for 64-bit machines) does not exist. SoftEther must be installed to this directory for Salmon to work: ");
	strcat(vpncmdErrMsg, g_vpncmdPath);
	logMajorError(vpncmdErrMsg);
	ExitProcess(0);
}

void reportSoftEtherError()
{
	DWORD retSize;
	LPTSTR pTemp = NULL;

	retSize = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY,
		NULL, GetLastError(), LANG_NEUTRAL, (LPTSTR)&pTemp, 0, NULL);

	MessageBoxW(NULL, pTemp, L"Error running SoftEther; is it installed correctly?", MB_OK);
	LocalFree(pTemp);
}

void systemNice(char* execMe)
{
	wchar_t toExecW[EXEC_VPNCMD_BUFSIZE];
	mbstowcs(toExecW, execMe, EXEC_VPNCMD_BUFSIZE);

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));


	if (!CreateProcess(NULL, toExecW, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
		reportSoftEtherError();
	WaitForSingleObject(pi.hProcess, INFINITE);
}



FILE* openConfigFile(const char* filename, const char* mode)
{
	char wholeThing[300];
	sprintf(wholeThing, "%s\\salmon\\%s", getenv("APPDATA"), filename);
	FILE* openedFile = fopen(wholeThing, mode);
	return openedFile;
}

void logToConfigFile(const char* theString, const char* theFile)
{
	time_t tempTime;
	time(&tempTime);
	char timeStr[50];
	ctime_s(timeStr, 50, &tempTime);
	if(strchr(timeStr, '\n'))
		*strchr(timeStr, '\n') = 0;

	FILE* theLogFile = openConfigFile(theFile, "at");
	fwrite(timeStr, 1, strlen(timeStr), theLogFile);
	fwrite(": ", 1, 2, theLogFile);
	fwrite(theString, 1, strlen(theString), theLogFile);
	fwrite("\n", 1, 1, theLogFile);
	fclose(theLogFile);
}
void logMajorNotification(const char* theString)
{
	logToConfigFile(theString, "SALMON_MAJOR_NOTIFICATION.txt");
}
void logMajorError(const char* theString)
{
	logToConfigFile(theString, "SALMON_MAJOR_ERRORS.txt");
	MessageBoxA(NULL, theString, "Salmon major error", MB_OK);
}
void logError(const char* theString)
{
	logToConfigFile(theString, "SALMON_ERRORS.txt");
}

void removeIconFromTray();
int exitErrorNoLog()
{
	char toExec[EXEC_VPNCMD_BUFSIZE];
	sprintf(toExec, "\"%s\" /server localhost /hub:salmon /password:%s /cmd offline", g_vpncmdPath, gAdminPass);
	systemNice(toExec);

	if (gServerOnline == SALMON_SERVER_ONLINE)
		stopServer();

	freeStuff();
	uninitTLS();
	removeIconFromTray();

	WSACleanup();
	ExitProcess(1);

	return 0;
}
void exitError(const char* errStr)
{
	logError(errStr);
	exitErrorNoLog();
}
void exitMajorError(const char* errStr)
{
	logMajorError(errStr);
	exitErrorNoLog();
}

void stopServer();
void genPassword()
{
	HCRYPTPROV cryptProvider = 0;
	CryptAcquireContext(&cryptProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	CryptGenRandom(cryptProvider, DIRSERV_PASSWORD_LENGTH, (BYTE*)gDirServPassword);
	
	//NOTE: gDirServPassword is exactly DIRSERV_PASSWORD_LENGTH; not null terminated
	for(int i = 0; i < DIRSERV_PASSWORD_LENGTH; i++)
		gDirServPassword[i] = 33 + ((unsigned char)gDirServPassword[i]) % (127 - 33);

	FILE* writePW = openConfigFile("salmon_dirserv_pw", "wt");
	if(!writePW)
	{
		logMajorError("Could not access %APPDATA%\\salmon\\salmon_dirserv_pw! Please ensure that the directory exists, and the file is not read-only. Or, reinstall Salmon+SoftEther.");
		stopServer();
	}

	fwrite(gDirServPassword, 1, DIRSERV_PASSWORD_LENGTH, writePW);

	//I'm just going to throw the IPSec PSK in here too, because it and the dirserv pw are both
	//fundamentally the same - a random string shared with the dir server at registration.
	int charsGotten = 0;
	gMyPSK[IPSEC_PSK_LENGTH] = 0;
	while (charsGotten < IPSEC_PSK_LENGTH)
	{
		char tryChar;
		CryptGenRandom(cryptProvider, 1, (BYTE*)&tryChar);

		if (isalnum(tryChar)) //this gets passed into system(), so keep it clean
		{
			gMyPSK[charsGotten] = tryChar;
			charsGotten++;
		}
	}
	fwrite(gMyPSK, 1, IPSEC_PSK_LENGTH, writePW);
	fclose(writePW);
	CryptReleaseContext(cryptProvider, 0);
}

int readPWPSK()
{
	//NOTE this program is supposed to generate and store a dirserv pw if there isn't one yet.
	//		linux version fails here if it can't open the file for reading, because if the file
	//		doesn't exist with good permissions, we won't have the ability to create it (it's in /var/lib).
	//		on windows, the privilege stuff won't be a problem, so we can recover from this situation - 
	//		just report "unable to open file" as "0 bytes read."
	FILE* readPW = openConfigFile("salmon_dirserv_pw", "rb");
	if (!readPW)
		return 0;

	int pwReadLen = fread(gDirServPassword, 1, DIRSERV_PASSWORD_LENGTH, readPW);
	//IPSec PSK is now tacked onto the end of the dirserv pw file
	memset(gMyPSK, 0, IPSEC_PSK_LENGTH);
	pwReadLen += fread(gMyPSK, 1, IPSEC_PSK_LENGTH, readPW);
	gMyPSK[IPSEC_PSK_LENGTH] = 0;
	fclose(readPW);

	return pwReadLen;
}

void ensureCertFile()
{
	FILE* testCertFile = openConfigFile("my_softether_cert.crt", "rt");
	if (!testCertFile)
	{
		//the linux daemon gives up here due to daemon problems (softether gets weird about paths...)
		//no such problems in the windows service version, so generate the cert here
		char certPath[300];
		sprintf(certPath, "%s\\salmon\\my_softether_cert.crt", getenv("APPDATA"));

		char toExec[EXEC_VPNCMD_BUFSIZE];
		sprintf(toExec, "%s /server localhost /password:%s /cmd servercertget %s", g_vpncmdPath, gAdminPass, certPath);
		systemNice(toExec);

		int readTries = 0; //deal with softether asynchronicity
		for (readTries = 0; readTries < 5; readTries++)
		{
			testCertFile = openConfigFile("my_softether_cert.crt", "rt");
			if (testCertFile)
				break;
			Sleep(500);
		}

		if (!testCertFile)
			exitMajorError("Could not read or write %APPDATA%\\salmon\\my_softether_cert.crt! Please ensure the path exists, and the file is not read-only. Or, reinstall Salmon+SoftEther.");
	}
	fclose(testCertFile);
}

int getline(char **lineptr, size_t *n, FILE *stream);
void loadSettings()
{
	BOOL useDefaults = TRUE;

	FILE* readSettings = openConfigFile("salmon_settings", "rt");
	if(readSettings)
	{
		useDefaults = FALSE;

		//when loadSettings() is called, gOfferedBW etc should all be null, so getline() will malloc() for us.
		size_t dummyLen = 0;
		//NOTE these aren't the final time strings; see below
		if(getline(&gOfferedBW, &dummyLen, readSettings)<=1)//getline's count includes newline
			useDefaults = TRUE;
		dummyLen = 0;
		if(getline(&gServerUpTime, &dummyLen, readSettings)<=2)
			useDefaults = TRUE;
		dummyLen = 0;
		if(getline(&gServerDownTime, &dummyLen, readSettings)<=2)
			useDefaults = TRUE;
		dummyLen = 0;

		//we really need that password!
		if (getline(&gAdminPass, &dummyLen, readSettings) <= 2)
			exitMajorError("Invalid Softether admin password! Please reinstall the whole Salmon+Softether package.");

		fclose(readSettings);
		
		if (strchr(gOfferedBW, '\n'))
			*strchr(gOfferedBW, '\n') = 0;
		if (strchr(gServerUpTime, '\n'))
			*strchr(gServerUpTime, '\n') = 0;
		if (strchr(gServerDownTime, '\n'))
			*strchr(gServerDownTime, '\n') = 0;
		if (strchr(gAdminPass, '\n'))
			*strchr(gAdminPass, '\n') = 0;
	}
	else
		exitMajorError("%APPDATA%\\salmon\\salmon_settings is missing! Please reinstall the whole Salmon+Softether package.");
	
	//NOTE since getline() was definitely called on gOfferedBW and serverUp/DownTime, they have
	//	definitely been malloc()'d, so it's safe to just free them without checking if they're still 0,
	//	and also safe to call strstr() on them.
	if (useDefaults)
	{
		free(gOfferedBW);
		free(gServerUpTime);
		free(gServerDownTime);
		gOfferedBW = strdup("100");
		gServerUpTime = strdup("NEVER");
		gServerDownTime = strdup("NEVER");
	}
	else if (strstr(gServerUpTime, "NEVER") || strstr(gServerDownTime, "NEVER"))
	{
		free(gServerUpTime);
		free(gServerDownTime);
		gServerUpTime = strdup("NEVER");
		gServerDownTime = strdup("NEVER");
	}
	else
	{
		//NOTE expected time format: 2014-07-12T01:01:00
		//     what will be in file (if not NEVER): 01:01
		//so, tack on that other stuff in front and back.
		char* temp = malloc(strlen("2014-07-01T") + strlen(gServerUpTime) + strlen(":00") + 1);
		sprintf(temp, "2014-07-01T%s:00", gServerUpTime);
		free(gServerUpTime);
		gServerUpTime = temp;

		//NOTE no, we don't need to worry about adding to the date if the times wrap around
		temp = malloc(strlen("2014-07-01T") + strlen(gServerDownTime) + strlen(":00") + 1);
		sprintf(temp, "2014-07-01T%s:00", gServerDownTime);
		free(gServerDownTime);
		gServerDownTime = temp;
	}
	
	//TODO RESTORE AND UPDATE THIS CODE IF WE EVER MANAGE ANY SORT OF NAT IN WINDOWS
	gUseSoftEtherSecureNAT = TRUE;
	/*gUseSoftEtherSecureNAT=FALSE;
	FILE* readNATsetting = openConfigFile("softetherSecureNAT", "rt");
	if(readNATsetting)
	{
		char tempNATbuf[10];
		memset(tempNATbuf, 0, 10);
		fread(tempNATbuf, 1, 5, readNATsetting);
		fclose(readNATsetting);
		if(!strncmp(tempNATbuf, "yes", 3))
			gUseSoftEtherSecureNAT=TRUE;
	}

	if(!gUseSoftEtherSecureNAT)
	{
		FILE* readBaseTapIP = openConfigFile("tapIP", "rt");
		if(readBaseTapIP)
		{
			size_t dummyLen = 0;
			getline(&gTapBaseIP, &dummyLen, readBaseTapIP);
			fclose(readBaseTapIP);
			if(strchr(gTapBaseIP, '\n'))
				*strchr(gTapBaseIP, '\n')=0;
		}
		else
			logError("Could not read %APPDATA%\\salmon\\tapIP");
	}
	else*/
	{
		//NOTE: this is used in dhcpset, regardless of whether real NAT or SecureNAT is used!
		gTapBaseIP = strdup("192.168.30");//softether's default
	}
}

void wipePassword()
{
	FILE* wipePW = openConfigFile("salmon_dirserv_pw", "wt");
	if(!wipePW)
		exitError("Could not open password file for wiping.");
	else
	{
		fwrite("invalidpass", 1, 11, wipePW);
		fclose(wipePW);
	}
}

void hton64(uint64_t* output, uint64_t input)
{
	int checkEndianness = 1;
	if (*(char*)&checkEndianness != 1)//big endian
	{
		*output = input;
		return;
	}

	char* inBytes = (char*)&input;
	char* outBytes = (char*)output;
	int i = 0;
	for (i = 0; i < 8; i++)
		outBytes[i] = inBytes[7 - i];
}

uint16_t writeSendLen(char* dest, char* strlenOfThis)
{
	unsigned long int theLen = strlen(strlenOfThis);
	if(theLen > 65535)
	{
		logError("Tried to send a string longer than 65535 to directory server.");
		return htons(65535);
	}
	uint16_t toSend = (uint16_t)theLen;
	uint16_t netOrder = htons(toSend);
	memcpy(dest, &netOrder, 2);
	return toSend;
}

void freeStuff()
{
	if(gOfferedBW)
		free(gOfferedBW);
	if(gServerUpTime)
		free(gServerUpTime);
	if(gServerDownTime)
		free(gServerDownTime);
	if(gAdminPass)
		free(gAdminPass);
	if(gTapBaseIP)
		free(gTapBaseIP);
	gOfferedBW = gServerUpTime = gServerDownTime = gAdminPass = gTapBaseIP = 0;
}

//in hnsecs since jan 1, 1601
__int64 getHNSecsNow()
{
	SYSTEMTIME temp;
	GetLocalTime(&temp);
	FILETIME ftemp;
	SystemTimeToFileTime(&temp, &ftemp);
	ULARGE_INTEGER ti;
	ti.LowPart = ftemp.dwLowDateTime;
	ti.HighPart = ftemp.dwHighDateTime;
	return ti.QuadPart;
}
