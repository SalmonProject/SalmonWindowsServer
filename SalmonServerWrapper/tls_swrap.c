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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "polarssl/ssl.h"
#include "polarssl/sha1.h"

#include "constants.h"
#include "globals.h"

#include "connect_tls.h"
#include "connection_logic.h"
#include "utility.h"
#include "pipefile.h"

//equivalent to strptime(dateTimeStr, "%Y-%m-%d %H:%M:%S", &tempTime);
void ughHomebrew_strptime(const char* dateTimeStr, struct tm *tempTime)
{
	if (strlen(dateTimeStr) > 99)
		goto TimeFormatError;
	char lolTemp[100];
	strcpy(lolTemp, dateTimeStr);
	if (!strchr(lolTemp, '-'))
		goto TimeFormatError;
	*strchr(lolTemp, '-') = 0;
	int realYear = atoi(lolTemp);
	tempTime->tm_year = realYear - 1900;

	strcpy(lolTemp, dateTimeStr);
	char* curToken = strchr(lolTemp, '-') + 1;
	if(!strchr(curToken, '-'))
		goto TimeFormatError;
	*strchr(curToken, '-') = 0;
	int realMonth = atoi(curToken);
	tempTime->tm_mon = realMonth - 1;

	strcpy(lolTemp, dateTimeStr);
	curToken = strchr(lolTemp, '-') + 1;
	curToken = strchr(curToken, '-') + 1;
	if(!strchr(curToken, ' '))
		goto TimeFormatError;
	*strchr(curToken, ' ') = 0;
	tempTime->tm_mday = atoi(curToken);

	strcpy(lolTemp, dateTimeStr);
	curToken = strchr(lolTemp, ' ') + 1;
	if (!strchr(curToken, ':'))
		goto TimeFormatError;
	*strchr(curToken, ':') = 0;
	tempTime->tm_hour = atoi(curToken);

	strcpy(lolTemp, dateTimeStr);
	curToken = strchr(lolTemp, ':') + 1;
	if (!strchr(curToken, ':'))
		goto TimeFormatError;
	*strchr(curToken, ':') = 0;
	tempTime->tm_min = atoi(curToken);

	strcpy(lolTemp, dateTimeStr);
	curToken = strchr(lolTemp, ':') + 1;
	curToken = strchr(lolTemp, ':') + 1;
	tempTime->tm_sec = atoi(curToken);

	return;

TimeFormatError:
	tempTime->tm_sec = 0;
	char* errorString = (char*)malloc(strlen("Softether gave a date+time in an unexpected format: ") + strlen(dateTimeStr) + 1);
	sprintf(errorString, "Softether gave a date+time in an unexpected format: %s", dateTimeStr);
	logError(errorString);
	free(errorString);
}

BOOL tryServerUp();

int getline(char **lineptr, size_t *n, FILE *stream);
DWORD WINAPI usageReporter(LPVOID dummyarg)
{
	//NOTE max email address length is 254, so this should be fine.
	char curUsageUserName[300];
	memset(curUsageUserName, 0, 300);
	Sleep(10000);

	char* usageReportRaw = 0;
	while(1)
	{
		WaitForSingleObject(gUsageReportMutex, INFINITE);
		usageReportRaw = malloc(1024*64);
		char* usageReport = usageReportRaw+sizeof(uint16_t);

		char toExec[EXEC_VPNCMD_BUFSIZE];
		sprintf(toExec, "\"%s\" /server localhost /hub:salmon /password:%s /cmd userlist", g_vpncmdPath, gAdminPass);
		PIPEFILE* userLister = popenRNice(toExec);
		if(!userLister)
		{
			logError("Could not run userlist on SoftEther.");
			goto Bed;
		}
		usageReport[0] = 0;
		char* lineGetter = 0;
		size_t dummyLen;

		while(getlinePipe(&lineGetter, &dummyLen, userLister) > 0)
		{
			if(strstr(lineGetter, "User Name") && strchr(lineGetter, '|'))
			{
				strcpy(curUsageUserName, strchr(lineGetter, '|')+1);
				if(strchr(curUsageUserName, '\n'))
					*strchr(curUsageUserName, '\n')=0;
			}
			else if(strstr(lineGetter, "Last Login") && strchr(lineGetter, '|'))
			{
				if(strstr(lineGetter, "(None)"))
				{
					//curUserName gets score 0
					strcat(usageReport, curUsageUserName);
					strcat(usageReport, ":..@..:");
					strcat(usageReport, "0\n");
				}
				//very basic sanity check on format
				else if(strchr(lineGetter, ')') && strchr(lineGetter, '-') && strchr(lineGetter, ':'))
				{
					//yikes! time to extract the date and time. hooray for string processing in C...
					char* getDate = strchr(lineGetter, '|')+1;
					char dateStr[100];
					memset(dateStr, 0, 100);
					strcpy(dateStr, getDate);
					if(!strchr(dateStr, ' '))
						goto Bed;
					*strchr(dateStr, ' ') = 0;
					char* getTime = strchr(getDate, ')');
					while(*getTime < '0' || *getTime > '9')
						getTime++;
					
					char timeStr[30];
					strcpy(timeStr, getTime);
					if(strchr(timeStr, '\n'))
						*strchr(timeStr, '\n')=0;

					char dateTimeStr[60];
					strcpy(dateTimeStr, dateStr);
					strcat(dateTimeStr, " ");
					strcat(dateTimeStr, timeStr);

					struct tm tempTime;
					memset(&tempTime, 0, sizeof(struct tm));
					//strptime(dateTimeStr, "%Y-%m-%d %H:%M:%S", &tempTime);
					ughHomebrew_strptime(dateTimeStr, &tempTime);
					time_t timeSSE = mktime(&tempTime);

					//put the user's name in the report...
					strcat(usageReport, curUsageUserName);
					strcat(usageReport, ":..@..:");
					//now check last connection time to decide what score to give
					//curUserName gets score 100 if connected within the last 2 days, 25 else
					if(time(0) - timeSSE < 60 * 60 * 24 * 2)
						strcat(usageReport, "100\n");
					else
						strcat(usageReport, "25\n");
				}
				else
					logError("SoftEther's UserList gave us a weirdly formatted Last Login field...");
			}
		}
		pcloseNice(userLister);
		

		//the usage report is almost finished: now just tack on the final item, total bytes.
		long long unsigned int totalKBytes=0; //kilo, not kebi: power of 10, not 2.

		sprintf(toExec, "\"%s\" /server localhost /password:%s /cmd hublist", g_vpncmdPath, gAdminPass);
		PIPEFILE* hubLister = popenRNice(toExec);
		if (!hubLister)
		{
			logError("Could not run hublist on SoftEther.");
			goto Bed;
		}
		BOOL foundSalmonHub=FALSE;
		while(getlinePipe(&lineGetter, &dummyLen, hubLister) > 0)
		{
			if(foundSalmonHub && strstr(lineGetter, "Transfer Bytes"))
			{
				char* numberStart = strchr(lineGetter, '|')+1;
				char withoutCommas[60];
				memset(withoutCommas, 0, 60);
				int i;
				for(i=0; i<60 && (*numberStart >= '0' && *numberStart <= '9' || *numberStart == ','); numberStart++)
					if(*numberStart >= '0' && *numberStart <= '9')
					{
						withoutCommas[i] = *numberStart;
						i++;
					}

				//divide by 2 because softether appears to count both incoming and outgoing bytes;
				//there is of course one incoming AND one outgoing for each one of the user's bytes.
				//divide by 1000 to get KB: softether reports the number in bytes.
				totalKBytes = (strtoull(withoutCommas, 0, 10)/1000)/2;
				break;
			}
			else if(strstr(lineGetter, "Virtual Hub Name")&&strstr(lineGetter, "salmon"))
				foundSalmonHub=TRUE;
		}
		pcloseNice(hubLister);
		
		
		
		char totalBytesLine[70];

		sprintf(totalBytesLine, ":.bw.@.bw.:%llu", totalKBytes);
		strcat(usageReport, totalBytesLine);
		if(lineGetter)
			free(lineGetter);





		//now we're done building the message. time to send it.
		int reportSocket;
		if(net_connect(&reportSocket, SERVER_NAME, SERVER_PORT) != 0)
		{
			//NOTE this isn't THAT bad. just skip this report.
			goto Bed;
		}
		ssl_context* sslReport = TLSwithDir(&reportSocket);
		if(!sslReport)
		{
			shutdownWaitTLS(sslReport, reportSocket);
			goto Bed;
		}
		char dirResponse = authenticateWithDir(sslReport, 'g');
		if(dirResponse=='K')
		{
			//NOTE NOTE now network order
			uint16_t bytesSending = writeSendLen(usageReportRaw, usageReport);
			sendTLS(sslReport, usageReportRaw, sizeof(uint16_t) + bytesSending);
		}
		else
		{
			//i mean, this is definitely bizarre... but just skip this report.
			shutdownWaitTLS(sslReport, reportSocket);
			goto Bed;
		}
		shutdownWaitTLS(sslReport, reportSocket);

		//in case IP address has changed without the server restarting
		tryServerUp();

Bed:
		free(usageReportRaw);
		ReleaseMutex(gUsageReportMutex);
		Sleep((60*60*24 + 60) * 1000);
	}
}


//call with (0, -1) if you want it do the connection from scratch, or (fd, 0) if you already have a socket but no ssl
BOOL tryServerUpHaveConn(ssl_context* ssl, int theSocket)
{
	int ourSocket = theSocket;
	if (ourSocket < 0 && net_connect(&ourSocket, SERVER_NAME, SERVER_PORT) != 0)
	{
		shutdownWaitTLS(ssl, theSocket);
		exitError("Could not connect to the directory server for serverUp.");
	}
	if (!ssl && !(ssl = TLSwithDir(&ourSocket)))
	{
		shutdownWaitTLS(ssl, theSocket);
		exitError("Could not TLS to the directory server for serverUp.");
	}

	char dirResponse = authenticateWithDir(ssl, 'u');
	if (dirResponse == 'K')
	{
		BOOL upSucceeded = serverUp(ssl);
		shutdownWaitTLS(ssl, theSocket);
		return upSucceeded;
	}
	else
	{
		shutdownWaitTLS(ssl, theSocket);
		return FALSE;
	}
}

//call with (0, -1) if you want it do the connection from scratch, or (fd, 0) if you already have a socket but no ssl
BOOL tryRegisterHaveConn(ssl_context* ssl, int theSocket)
{
	int ourSocket = theSocket;
	if (ourSocket < 0 && net_connect(&ourSocket, SERVER_NAME, SERVER_PORT) != 0)
	{
		shutdownWaitTLS(ssl, theSocket);
		exitError("Could not connect to the directory server for registration.");
	}
	if (!ssl && !(ssl = TLSwithDir(&ourSocket)))
	{
		shutdownWaitTLS(ssl, theSocket);
		exitError("Could not TLS to the directory server for registration.");
	}
	//Fill gDirServPassword+gMyPSK, and save it the pw file. This overwrites any previous info, so we do it only after
	//a successful TLSwithDir(), so it's less likely we wipe out possibly useful info in doing a procedure that was going to fail anyways.
	genPassword();

	//Go through the registration process (authenticateWithDir() will use the newly generated pw)
	char dirResponse = authenticateWithDir(ssl, 'r');
	if (dirResponse == 'K')
	{
		BOOL amRegistered = registerSelf(ssl);
		shutdownWaitTLS(ssl, theSocket);
		return amRegistered;
	}
	else
	{
		shutdownWaitTLS(ssl, theSocket);
		return FALSE;
	}
}

BOOL tryRegister() { return tryRegisterHaveConn(0, -1); }
BOOL tryServerUp() { return tryServerUpHaveConn(0, -1); }

void updateTooltip(int curBWUsed, int numUsersConnected);
DWORD WINAPI monitorUsersBandwidth(LPVOID dummyarg);
int initTLS();
//attempt to do startup stuff, and then go into the main connection accepting loop.
//the startup stuff is to send a server-up message, or register if necessary.
void startServer()
{
	gServerOnline = SALMON_SERVER_CONNECTING;
	updateTooltip(0, 0);

	//======================================================================
	//read settings files: dirserv pw, PSK, our certificate, offered BW, etc
	//======================================================================

	//read into gDirServPassword and gMyPSK. 
	int pwReadLen = readPWPSK();

	//read into gAdminPass, gOfferedBW etc from %APPDATA%\salmon\salmon_settings if it's valid. (load defaults if it's not valid.)
	loadSettings();

	//Bring the SoftEther server online. (Only necessary in Windows version).
	//(must be done right here because we need the softether pw from loadSettings(), but the cert stuff might call softether.)
	char toExec[EXEC_VPNCMD_BUFSIZE];
	sprintf(toExec, "\"%s\" /server localhost:5555 /password:%s /cmd listenerenable 443", g_vpncmdPath, gAdminPass);
	systemNice(toExec);
	sprintf(toExec, "\"%s\" /server localhost:5555 /hub:salmon /password:%s /cmd online", g_vpncmdPath, gAdminPass);
	systemNice(toExec);
	sprintf(toExec, "\"%s\" /server localhost /hub:salmon /password:%s /cmd online", g_vpncmdPath, gAdminPass);
	systemNice(toExec);

	//Limit simultaneous clients to 4 - necessary for the Windows version's hacky attempt at reasonable rate limiting with the minimal tools available.
	sprintf(toExec, "\"%s\" /server localhost:5555 /hub:salmon /password:%s /cmd setmaxsession 4", g_vpncmdPath, gAdminPass);
	systemNice(toExec);
	sprintf(toExec, "\"%s\" /server localhost /hub:salmon /password:%s /cmd setmaxsession 4", g_vpncmdPath, gAdminPass);
	systemNice(toExec);

	//ensure softether correctly exported its automatically generated certificate to %APPDATA%\my_softether_cert.crt
	//if it didn't, have softether export it now (NOTE: Linux version would instead give up and exit).
	ensureCertFile();
	
	

	//===================================================================
	//connect to dir server, either to register, or to tell it we're back
	//===================================================================

	//just give up if we can't initTLS().
	if (initTLS())
		exitError("Failed to initialize PolarSSL.");

	int theSocket;

	//If can't connect to directory server, that might be because the server computer's internet connection
	//isn't up yet. After all, this program runs at startup. Even though normal networking might be all up
	//and running by the time this is started, what about a USB wireless card, like on my desktop? So, just
	//to be safe, keep trying over the course of a minute.
	int netConRes = -1;
	int connectTries = 0;
	time_t firstConTryTime = time(0);
	while (netConRes != 0 && connectTries < 6 && time(0) - firstConTryTime < 60)
	{
		netConRes = net_connect(&theSocket, SERVER_NAME, SERVER_PORT);
		connectTries++;
		if (netConRes != 0)
			Sleep(10000);
	}
	if (connectTries >= 6 && netConRes != 0 && net_connect(&theSocket, SERVER_NAME, SERVER_PORT) != 0)
		exitError("Could not connect to the directory server.");

	ssl_context* ssl = TLSwithDir(&theSocket);
	if (!ssl)
	{
		//NOTE ok to call shutdownTLS on null ssl because it's checked for in the function.
		//(we are calling shutdown to close the net_connect()'d theSocket)
		shutdownTLS(ssl, theSocket);
		exitError("Failed to establish TLS session with directory server.");
	}


	//if we don't have a good looking salmon_dirserv_pw file, then try to register
	if (pwReadLen != DIRSERV_PASSWORD_LENGTH + IPSEC_PSK_LENGTH)
	{
		if (tryRegisterHaveConn(ssl, theSocket))
		{
			if(!tryServerUp())
				exitError("Registered, but directory server responded weirdly to our server-up message.");
		}
		else
			exitError("Registration with a newly generated password failed, even though we were able to correctly communicate with the directory server.");
	}
	else //report in to the dir as an existing server
	{
		if (!tryServerUpHaveConn(ssl, theSocket))
		{
			if (tryRegister())
			{
				if(!tryServerUp())
					exitError("We had a password but failed to server-up, then succeeded with a fresh registration, but the server-up with the new password also failed... very strange.");
			}
			else
				exitError("We had a password and connected to the directory server, but the server-up and fallback re-register attempts both failed.");
		}
	}



	//==========================
	//post-dirserv-contact logic
	//==========================

	gServerOnline = SALMON_SERVER_ONLINE;
	updateTooltip(0, 0);

	//NOTE: gTimeStartedAt must be set before any dir serv connections are accepted: we are supposed to report "wasdown"
	//		to block checks for the first 5 minutes after coming up; gTimeStartedAt is the variable checked.
	gTimeStartedAt = time(0);

	//report users' bandwidth use to the directory server ~once per day
	if (gUsageReporterHandle == NULL)
		gUsageReporterHandle = CreateThread(NULL, 0, usageReporter, NULL, 0, NULL);
	else
		ResumeThread(gUsageReporterHandle);

	//handle any messages the directory server sends us
	gActuallyAcceptConnections = TRUE;
	if (gAcceptConnectionsHandle == NULL)
		gAcceptConnectionsHandle = CreateThread(NULL, 0, acceptConnections, NULL, 0, NULL);
	//(this thread is controlled by gActuallyAcceptConnections; there is no suspending/resuming)

	//keep the tray icon's popup bubble thing updated with number of connected users+BW used.
	if (gMonitorBWUsersHandle == NULL)
		gMonitorBWUsersHandle = CreateThread(NULL, 0, monitorUsersBandwidth, NULL, 0, NULL);
	else
		ResumeThread(gMonitorBWUsersHandle);
}
