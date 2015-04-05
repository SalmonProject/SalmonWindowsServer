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

#ifndef _SALMON_WINDOWS_SERVER_WRAPPER_GLOBALS_INCLGUARD_
#define _SALMON_WINDOWS_SERVER_WRAPPER_GLOBALS_INCLGUARD_

#include <Windows.h>

#include <time.h>

#include "constants.h"

//The password the wrapper uses to identify itself to the directory server.
//IMPORTANT NOTE: currently NOT null terminated!!! We're just using memcpy(DIRSERV_PASSWORD_LENGTH).
extern char gDirServPassword[DIRSERV_PASSWORD_LENGTH];
//The SoftEther server's IPSec PSK
extern char gMyPSK[IPSEC_PSK_LENGTH + 1];

//Time the server was last started. Gets set at the end of a successful serverUp().
//Used to decide whether to respond "wasdown" (started <5 minutes ago) to block checks.
extern time_t gTimeStartedAt;

//If false, the acceptConnections() thread continues accepting connections, but closes
//them as soon as they have been accepted, with no messages/logic happening. Basically, a
//way to suspend the thread without dealing with some messiness (see acceptConnections()).
extern BOOL gActuallyAcceptConnections;

//Are both SoftEther and the acceptConnections() thread are up and running? Values:
//SALMON_SERVER_OFFLINE, SALMON_SERVER_CONNECTING, SALMON_SERVER_ONLINE
char gServerOnline;

//Full path for vpncmd.exe. load_vpncmdexe_Path() loads it.
extern char g_vpncmdPath[VPNCMDPATH_BUFSIZE];

//stopServer() SuspendThread()s the usageReporter() thread. In the rare event that 
//stopServer() is called while a usage report is happening, it should wait (a little 
//while) for the report to finish.
extern HANDLE gUsageReportMutex;

//Handles for the 3 threads: usageReporter(), acceptConnections(), and monitorUsersBandwidth
extern HANDLE gUsageReporterHandle;
extern HANDLE gAcceptConnectionsHandle;
extern HANDLE gMonitorBWUsersHandle;

//Whether to use SoftEther's built-in "Secure NAT". (Currently, Windows must use it).
extern BOOL gUseSoftEtherSecureNAT;
//If we're doing iptables NAT on Linux, this is a string of the first 3 octets of the
//tap interface. Install script currently chooses gTapBaseIP="192.168.176" by default.
extern char* gTapBaseIP;

//One string for each line that is supposed to be in salmon_settings. malloc()'d and
//set by loadSettings(), free()d by freeStuff().
extern char* gOfferedBW;//string integer, in KB/s
extern char* gServerUpTime;
extern char* gServerDownTime;
extern char* gAdminPass;

//Here in the Windows version, we are limiting ourselves to 4 concurrent users. That
//means that a connection can get turned away from a perfectly fine server, which would
//look like a block. To avoid that, the server should know to say 'wasdown' if it gets
//block checked while 4 people are connected.
extern time_t gLastHad4Users;

#endif //_SALMON_WINDOWS_SERVER_WRAPPER_GLOBALS_INCLGUARD_