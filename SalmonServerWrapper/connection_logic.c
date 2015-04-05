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
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment (lib, "Ws2_32.lib")

#include "polarssl/base64.h"

#include "constants.h"
#include "globals.h"

#include "connect_tls.h"
#include "control_softether.h"
#include "utility.h"
#include "pipefile.h"
#include "connection_logic.h"



int getline(char **lineptr, size_t *n, FILE *stream);
void stopServer();
void updateTooltip(int curBWUsed, int numUsersConnected);

char authenticateWithDir(ssl_context* ssl, char command)
{
	//regardless of what we're going to be doing, we start by sending our password to authenticate ourself.
	//NOTE yes you send the password even if you're registering
	//NOTE NOTE for password, we don't do the ushort bytesSending thing, because it's fixed length
	sendTLS(ssl, gDirServPassword, DIRSERV_PASSWORD_LENGTH);
	sendTLS(ssl, &command, 1);

	//directory server tells us if we should continue, or if it's aborting.
	//NOTE the response should be 'K' for OK, or 'I' for invalid password (either the password wasn't
	//found and you're doing a server up, or the password WAS found and you're registering.)
	char dirStatusResponse='X';
	recvTLS(ssl, &dirStatusResponse, 1);
	return dirStatusResponse;
}

BOOL recvCredentialList(ssl_context* ssl, char* theBuf, unsigned int maxBufLen)
{
	int offset=0;
	int bytesRead=maxBufLen-1;
	BOOL credentialsGood=TRUE;

	for(;	bytesRead!=0
	        &&!strstr(theBuf, "@@@ENDLIST@@@@@@ENDLIST@@@@@@ENDLIST@@@")
	        &&offset<maxBufLen
	        ; offset+=bytesRead)
		bytesRead = recvTLS(ssl, theBuf+offset, (maxBufLen-1)-offset);

	theBuf[offset] = 0;

	char* tempstrstropt;
	if((tempstrstropt=strstr(theBuf, "@@@ENDLIST@@@@@@ENDLIST@@@@@@ENDLIST@@@")))
		*tempstrstropt=0;
	else
		credentialsGood=FALSE;

	return credentialsGood;
}

//attempts to register with the dir server as a new server. returns 0 if not successful.
BOOL registerSelf(ssl_context* ssl)
{
	//register. start with our password (which server won't have in its db), then give command 'r'.
	//(NOTE: password has already been sent at this point.)
	char theMsg[6000];
	char* msgTextStart = theMsg+sizeof(uint16_t);
	memset(msgTextStart, 0, 6000 - sizeof(uint16_t));
	sprintf(msgTextStart, "%s\n%s\n%s\n%s\n", gOfferedBW, gServerUpTime, gServerDownTime, gMyPSK);

	FILE* readNotifyEmail = openConfigFile("notify_email", "rt");
	if(!readNotifyEmail)
		strcat(msgTextStart, "!#$%^NONE!#$%^\n");
	else
	{
		char theEmailAddr[300];
		int charsRead = fread(theEmailAddr, 1, 299, readNotifyEmail);
		theEmailAddr[charsRead] = 0;
		fclose(readNotifyEmail);
		if (strchr(theEmailAddr, '\n'))
			*strchr(theEmailAddr, '\n') = 0;
		strcat(msgTextStart, theEmailAddr);
		strcat(msgTextStart, "\n");
	}

	FILE* readSoftetherCert = openConfigFile("my_softether_cert.crt", "rt");
	if(!readSoftetherCert)
	{
		logError("Somehow ended up trying to registerSelf() without a valid certificate.");
		return FALSE;
	}
	fread(msgTextStart + strlen(msgTextStart), 1, (6000 - sizeof(uint16_t)) - strlen(msgTextStart), readSoftetherCert);
	fclose(readSoftetherCert);

	//ensure the message we send ends with a \n
	if(msgTextStart[strlen(msgTextStart)-1]!='\n')
		strcat(msgTextStart, "\n");

	//do a send into vibe's fixed-size recv
	uint16_t bytesSending = writeSendLen(theMsg, msgTextStart);
	sendTLS(ssl, theMsg, sizeof(uint16_t) + bytesSending);

	char recvStatus[200];
	memset(recvStatus, 0, 200);
	recvTLS(ssl, recvStatus, 199);

	return strncmp(recvStatus, "OK", 2) ? FALSE : TRUE;
}



BOOL serverUp(ssl_context* ssl)
{
	//say "going up": send 'u', then our offered bandwidth and times of day
	char theMsg[10000];
	char* msgTextStart = theMsg+sizeof(uint16_t);

	sprintf(msgTextStart, "%s\n%s\n%s\n", gOfferedBW, gServerUpTime, gServerDownTime);

	//do a send into vibe's fixed-size recv
	uint16_t bytesSending = writeSendLen(theMsg, msgTextStart);
	sendTLS(ssl, theMsg, sizeof(uint16_t) + bytesSending);

	//now receive the list of credentials we should be accepting.
	memset(theMsg, 0, 10000);
	BOOL credentialsGood = recvCredentialList(ssl, theMsg, 10000);

	if(credentialsGood)
		setAcceptedCredentials(theMsg);
	else
		logError("Directory server gave us a malformed credentials list...");

	//NOTE: we used to set the rate limit to the value of gOfferedBW that we just now reported to the dir server.
	//		With the new rate limiting logic, that's all controlled in the monitorUsersBandwidth thread.

	return TRUE;
}

void respondAreYouStillThere(ssl_context* ssl)
{
	char pingReply[200];
	char* pingReplyText = pingReply + sizeof(uint16_t);
	memset(pingReply, 0, 200);

	sprintf(pingReplyText, "up\n%s\n%s\n%s\n", gOfferedBW, gServerUpTime, gServerDownTime);

	//we are sending to a vibedTLSreadBytes function, which expects an unsigned short int (2 bytes)
	//representing how many bytes will come after.
	uint16_t bytesSending = writeSendLen(pingReply, pingReplyText);
	sendTLS(ssl, pingReply, bytesSending + sizeof(uint16_t));

	memset(pingReply, 0, 200);
	int bytesRecvd = recvTLS(ssl, pingReply, 199);
	pingReply[bytesRecvd] = 0;
	//pingReply should now read "OK", but we don't really need to be sure... it was the
	//directory's idea to do this ping, so we don't care if it completes successfully.
}

void respondBlockCheck(ssl_context* ssl)
{
	//parse format: bCN^xyzusernamexyz,   where b was already read out of the stream before this function.
	char recvbuf[200];
	memset(recvbuf, 0, 200);
	int bytesRecvd = recvTLS(ssl, recvbuf, 199);
	char whichCountry[3];
	memcpy(whichCountry, recvbuf, 2);
	whichCountry[2] = 0;
	char userAccount[198];
	strcpy(userAccount, recvbuf + 3);

	//semi-HACK: for now, the block check logic is "if the dir server can reach me and the person can't, i'm blocked."

	//however, just in case salmond is running but vpnserver isn't, we'll check whether vpnserver is up:
	BOOL vpnserverWasDown = FALSE;
	char toExec[EXEC_VPNCMD_BUFSIZE];
	sprintf(toExec, "\"%s\" /server localhost /password:%s /cmd hublist", g_vpncmdPath, gAdminPass);
	PIPEFILE* hubLister = popenRNice(toExec);
	if (!hubLister)
	{
		logError("Could not run hublist on SoftEther.");
		return;
	}
	size_t lineGetterLen = 200;
	char* lineGetter = malloc(lineGetterLen);
	memset(lineGetter, 0, lineGetterLen);
	while (getlinePipe(&lineGetter, &lineGetterLen, hubLister) > 0)
	{
		if (strstr(lineGetter, "Error occurred"))
		{
			vpnserverWasDown = TRUE;
			break;
		}
	}
	pcloseNice(hubLister);
	free(lineGetter);

	uint16_t bytesSending;
	if (vpnserverWasDown)
	{
		strcpy(recvbuf + sizeof(uint16_t), "wasdown");
		bytesSending = writeSendLen(recvbuf, recvbuf + sizeof(uint16_t));
		sendTLS(ssl, recvbuf, bytesSending + sizeof(uint16_t));
		logError("The directory asked us to check if we were blocked, and it turned out that\nSoftEther's vpnserver wasn't running. salmond will terminate now. Hopefully, the next time the salmonandsoftether service is started, things will get back to a working state.");

		//don't need to shutdown here, because in the windows version, gracefulExit becomes stopServer()
		stopServer();
	}
	//if we started within the last 5 minutes, this block check is probably because someone tried to
	//talk to us while we were offline. report "wasdown" and just go on with your business.
	else if (time(0) - gTimeStartedAt < 300)
	{
		strcpy(recvbuf + sizeof(uint16_t), "wasdown");
		bytesSending = writeSendLen(recvbuf, recvbuf + sizeof(uint16_t));
		sendTLS(ssl, recvbuf, bytesSending + sizeof(uint16_t));
	}
	//(Windows version only) if we recently had our maximum of 4 users connected, this block check is probably from a user being turned away by that cap.
	else if (time(0) - gLastHad4Users < 300)
	{
		strcpy(recvbuf + sizeof(uint16_t), "wasdown");
		bytesSending = writeSendLen(recvbuf, recvbuf + sizeof(uint16_t));
		sendTLS(ssl, recvbuf, bytesSending + sizeof(uint16_t));
	}
	//verify that userAccount is an account in our softether salmon hub
	else if (!verifyUserAccount(userAccount))
	{
		//if we didn't have the account, it's fine, dir server will do a pleaseAddCredentials
		strcpy(recvbuf + sizeof(uint16_t), "didnthave");
		bytesSending = writeSendLen(recvbuf, recvbuf + sizeof(uint16_t));
		sendTLS(ssl, recvbuf, bytesSending + sizeof(uint16_t));
	}
	else
	{
		strcpy(recvbuf + sizeof(uint16_t), "blocked");
		bytesSending = writeSendLen(recvbuf, recvbuf + sizeof(uint16_t));
		sendTLS(ssl, recvbuf, bytesSending + sizeof(uint16_t));

		char notifyBuf[1000];

		if (!strcmp(whichCountry, "US"))
			strcpy(notifyBuf, "Your IP address may have been blocked, but the reporting user didn't specify a country.\n\n");
		else if (!strcmp(whichCountry, "IR"))
			strcpy(notifyBuf, "It appears that your IP address has been blocked in Iran.\n\n");
		else if (!strcmp(whichCountry, "CN"))
			strcpy(notifyBuf, "It appears that your IP address has been blocked in China.\n\n");
		else
			sprintf(notifyBuf, "It appears that your IP address has been blocked in %s.\n\n",
			whichCountry);
		strcat(notifyBuf, "If you can get a new IP address, you will be able to go back to serving these\n");
		strcat(notifyBuf, "blocked users as before. Getting a new IP address will not disrupt your Salmon\n");
		strcat(notifyBuf, "server, or any of your regular internet usage.\n\n");
		strcat(notifyBuf, "Instructions for a typical cable modem:\n");
		strcat(notifyBuf, "1) Unplug the power cord and router's ethernet cable from the modem.\n");
		strcat(notifyBuf, "2) Wait for about a minute.\n");
		strcat(notifyBuf, "3) Connect the modem to some other device via ethernet cable.\n");
		strcat(notifyBuf, "4) Power the modem back on, and wait a minute.\n");
		strcat(notifyBuf, "5) Power the modem off, wait a minute, and connect it to the router as it was\n");
		strcat(notifyBuf, "   at the beginning.\n");
		strcat(notifyBuf, "6) Power the modem back on.\n");
		logMajorNotification(notifyBuf);
	}
}

//
//
//
// ABOVE: the already-connected, logic-y stuff
// BELOW: the "make the connections happen" and "shutdown" stuff
//
//
//

DWORD WINAPI connectionThread(LPVOID arg)
{
	int ourSocket = *(int*)arg;
	free(arg);

	ssl_context* ssl = TLSwithDir(&ourSocket);
	if(!ssl)
	{
		net_close(ourSocket);
		logError("Accepted TCP connection, but failed to establish TLS session.");
		return 0;
	}

	//'z' is a placeholder command, since the situation here is "you're the one connecting to me;
	//I didn't have anything I wanted to do." You can think of it as "zzzz I was sleeping"! :)
	authenticateWithDir(ssl, 'z');


	//now the directory server should tell us which command it's doing
	char recvCommand=0;
	recvTLS(ssl, &recvCommand, 1);


	if(recvCommand=='p')//ping: the areYouStillThere function on the dir server
		respondAreYouStillThere(ssl);
	else if(recvCommand=='c')//dir server is telling us some new credentials we should allow
	{
		char credBuf[10000];
		memset(credBuf, 0, 10000);

		BOOL credentialsGood = recvCredentialList(ssl, credBuf, 10000);

		if(credentialsGood)
			setAcceptedCredentials(credBuf);
		else
			logError("Directory server gave us a malformed credentials list...");
	}
	else if(recvCommand=='b')//dir server is checking if we've been blocked in some country
		respondBlockCheck(ssl);
	else if (recvCommand == 'n')//dir server is sending us some special, human-written announcement
	{
		char* notifyBuf = 0;
		char* endPtr = 0;
		char recvBuf[1500];
		int bytesRecvd;
		int totalBytesRecvd = 0;
		while (totalBytesRecvd < 1024 * 1024 && (bytesRecvd = recvTLS(ssl, recvBuf, 1500)) > 0)
		{
			int oldTotalRecvd = totalBytesRecvd;
			totalBytesRecvd += bytesRecvd;
			notifyBuf = realloc(notifyBuf, totalBytesRecvd + 1);
			endPtr = notifyBuf + oldTotalRecvd;
			memcpy(endPtr, recvBuf, bytesRecvd);
			endPtr[bytesRecvd] = 0;
		}
		logMajorNotification(notifyBuf);
		free(notifyBuf);
	}
	else
	{
		char errBuf[100];
		sprintf(errBuf, "Server sent unknown command: \"%c\"", recvCommand);
		logError(errBuf);
	}
	shutdownWaitTLS(ssl, ourSocket);
	return 0;
}


DWORD WINAPI acceptConnections(LPVOID dummy)
{
	//int acceptedSocket;
	//int listenerSocket;

	//PolarSSL's net_bind() appears to be not quite as platform-independent
	//as they were going for. It's ok PolarSSL, I still love you.

	int iResult;

	SOCKET listenerSocket = INVALID_SOCKET;
	SOCKET acceptedSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL;
	struct addrinfo hints;

	// Initialize Winsock
	WSADATA wsaData;
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		MessageBoxA(NULL, "WSAStartup() failed; something must be very wrong!", "Network Error!", MB_OK);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, "7004", &hints, &result);
	if (iResult != 0) {
		MessageBoxA(NULL, "getaddrinfo() failed", "Network Error!", MB_OK);
		WSACleanup();
		return 1;
	}

	// Create a SOCKET for connecting to server
	listenerSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (listenerSocket == INVALID_SOCKET) {
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket
	iResult = bind(listenerSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		MessageBoxA(NULL, "bind() of TCP port 7004 failed", "Network Error!", MB_OK);
		freeaddrinfo(result);
		closesocket(listenerSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	iResult = listen(listenerSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		MessageBoxA(NULL,"listen() on bound TCP port 7004 failed" ,"Network Error!",MB_OK);
		closesocket(listenerSocket);
		WSACleanup();
		return 1;
	}

	//if(net_bind(&listenerSocket, NULL, 7004) != 0)
	//	exitError("Couldn't bind+listen port 7004 on any network interface!");

	while(1)
	{
		//I think if accept() actually fails, it's almost always going to be the type where every
		//call is going to immediately return with the same error, so rather than trying again and
		//again and generating a 10GB logError file, just exit.
		if(net_accept(listenerSocket, &acceptedSocket, NULL) != 0)
			exitError("Failed to accept a connection.");
		
		//Kinda-sorta HACK: I don't think we can just suspend the thread or else connection attempts will build up (and not be 
		//rejected, since there actually would be a listener on the port), and I don't see a clean way to have another thread break
		//the accept() loop without messy non-blocking polling stuff. I honestly think this is the cleanest approach: always have the
		//thread running, but just immediately shut down all connections when the server isn't supposed to be up.
		if (gActuallyAcceptConnections)
		{
			int* client_fd = (int*)malloc(sizeof(int));
			*client_fd = acceptedSocket;
			CreateThread(NULL, 0, connectionThread, (void*)client_fd, 0, NULL);
		}
		else
			net_close(acceptedSocket); //sorry client, we were just kidding about being here
	}
	return 0;
}


//say "going down" right before we stop the server. UDP to keep it quick.
void stopServer()
{
	unsigned char* hashIn = 0;
	char toExec[EXEC_VPNCMD_BUFSIZE];

	//Just setting the hub to offline doesn't stop the fake HTTPS server on 443 from functioning. If the fake HTTPS
	//server appears to be functioning, the block check logic will get messed up.
	sprintf(toExec, "\"%s\" /server localhost /password:%s /cmd listenerdisable 443", g_vpncmdPath, gAdminPass);
	systemNice(toExec);

	sprintf(toExec, "\"%s\" /server localhost:5555 /hub:salmon /password:%s /cmd offline", g_vpncmdPath, gAdminPass);
	systemNice(toExec);

	uninitTLS();

	//NOTE: waiting for gUsageReportMutex could in theory take several seconds, which isn't great. but, that's only
	//		if you get so unlucky as to hit its few-seconds-per-day report time, and even then it's just a little delay.
	//		However, it could hang (on net_connect) if the directory server doesn't respond. If we don't get the mutex
	//		within 10s, we'll assume that's what happened, panic, and die.
	DWORD waitRes = WaitForSingleObject(gUsageReportMutex, 10 * 1000);
	if (waitRes != WAIT_OBJECT_0 && waitRes != WAIT_ABANDONED)
	{
		DWORD retSize;
		LPTSTR pTemp = NULL;

		retSize = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY,
			NULL, GetLastError(), LANG_NEUTRAL, (LPTSTR)&pTemp, 0, NULL);

		MessageBoxW(NULL, pTemp, L"sadfsdfsadf?", MB_OK);
		LocalFree(pTemp);

		exitError("stopServer() didn't see the in-progress usage report finish gracefully; program exiting.");
	}
	if (gUsageReporterHandle != NULL)
		SuspendThread(gUsageReporterHandle);
	ReleaseMutex(gUsageReportMutex);

	SuspendThread(gMonitorBWUsersHandle);

	//NOTE: see acceptConnections() above to read how setting this to false halts the thread
	gActuallyAcceptConnections = FALSE;

	struct addrinfo* dirServInfo;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(SERVER_NAME, "3389", &hints, &dirServInfo) != 0)
		goto CouldntSendUDP;

	struct addrinfo* eachAddr;
	struct sockaddr* theSendAddr = NULL;
	int theSocket = -1;
	for (eachAddr = dirServInfo; eachAddr != NULL; eachAddr = eachAddr->ai_next)
		if ((theSocket = socket(eachAddr->ai_family, eachAddr->ai_socktype, eachAddr->ai_protocol)) >= 0)
		{
			theSendAddr = eachAddr->ai_addr;
			break;
		}

	if (theSocket < 0)
		goto CouldntSendUDP;

	time_t sse = time(0);
	//NOTE NOTE remember, network order! INCLUDING the time value that goes into the hash.
	uint64_t time64Bits = sse;
	uint64_t timeNetOrder;
	hton64(&timeNetOrder, time64Bits);
	unsigned char sendbuf[sizeof(uint64_t)+20];//sse, then a SHA-1 hash

	//first get how big the buffer for holding the base64 output needs to be
	//(calling base64_encode with destination null writes that value into bufSize)
	size_t bufSize = 0;
	base64_encode(0, &bufSize, gDirServPassword, DIRSERV_PASSWORD_LENGTH);

	//now actually base64 encode it
	hashIn = malloc(bufSize+sizeof(uint64_t));
	base64_encode(hashIn+sizeof(uint64_t), &bufSize, gDirServPassword, DIRSERV_PASSWORD_LENGTH);
	memcpy(hashIn, &timeNetOrder, sizeof(uint64_t));

	//now hash(time64Bits, base64(password))
	sha1(hashIn, bufSize+sizeof(uint64_t), sendbuf+sizeof(uint64_t));


	//send time64Bits, sha1(time64Bits, base64(pw))
	memcpy(sendbuf, &timeNetOrder, sizeof(uint64_t));

	//thanks to our basic anti-DoS logic, 3 isn't any more expensive/annoying for the directory than 1!
	//so, might as well raise the chance of the message not getting through to the 3rd power.
	sendto(theSocket, sendbuf, sizeof(uint64_t) + 20, 0, theSendAddr, sizeof(struct sockaddr));
	sendto(theSocket, sendbuf, sizeof(uint64_t) + 20, 0, theSendAddr, sizeof(struct sockaddr));
	sendto(theSocket, sendbuf, sizeof(uint64_t) + 20, 0, theSendAddr, sizeof(struct sockaddr));

	freeaddrinfo(dirServInfo);
	free(hashIn);
	//here in the windows version, this function doesn't exit the program, it just stops the server.
	//NOTE: freeStuff() covers everything malloc()'d in loadSettings().
	freeStuff();
	//exit(0);

	gServerOnline = SALMON_SERVER_OFFLINE;
	updateTooltip(0,0);

	return;

CouldntSendUDP:
	logError("Warning: stopServer() was unable to notify the directory server that we're going offline.");
	gServerOnline = SALMON_SERVER_OFFLINE;
	updateTooltip(0, 0);
	if(hashIn)
		free(hashIn);
	freeStuff();
}