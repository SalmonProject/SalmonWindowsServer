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
#include <string.h>

#include <Windows.h>

#include "constants.h"
#include "globals.h"

#include "utility.h"
#include "stringLL.h"
#include "pipefile.h"
#include "control_softether.h"


void ensurePortBlocks(char* hubName);

void ensureHub(char* hubName)
{
	//if this is the first time this function has been called, the "hubName" hub won't exist.
	//if that's the case, then create it now.
	char toExec[EXEC_VPNCMD_BUFSIZE];
	sprintf(toExec, "\"%s\" /server localhost /password:%s /cmd hublist", g_vpncmdPath, gAdminPass);
	PIPEFILE* hubLister = popenRNice(toExec);
	if(!hubLister)
	{
		logError("Could not run hublist on SoftEther.");
		return;
	}

	char hubExists = 0;

	size_t lineGetterLen = 200;
	char* lineGetter = malloc(lineGetterLen);
	memset(lineGetter, 0, lineGetterLen);
	while(getlinePipe(&lineGetter, &lineGetterLen, hubLister) > 0)
	{
		if(strstr(lineGetter, hubName) && strstr(lineGetter, "Virtual Hub Name"))
		{
			hubExists = 1;
			break;
		}
	}
	pcloseNice(hubLister);
	free(lineGetter);


	if(!hubExists)
	{
		sprintf(toExec, "\"%s\" /server localhost /password:%s /cmd hubcreate %s /password:%s",
					g_vpncmdPath, gAdminPass, hubName, gAdminPass);
		systemNice(toExec);
		//it looks like vpncmd might return before the change is fully "in effect" in
		//the actual server process... this sleep ought to fix the "could not userlist" error.
		//(as well as ensure that the next two commands will be applied to a hub that exists.)
		Sleep(2*1000);
	}
	
	//ensures access control rules (only http(s) etc are allowed) have been applied; applies if not
	ensurePortBlocks(hubName);

	//regardless of whether the hub needed to be created, ensure its [chosen NAT method] and DHCP server are on.
	//NOTE the apparent async nature of vpncmd makes me nervous, so i'd rather not rely on that sleep(2) up there.
	//so, just doing this every time seems safest. they're all simple idempotent "set to this value" ops anyways.
	if(gUseSoftEtherSecureNAT)
	{
		sprintf(toExec, "\"%s\" /server localhost /hub:%s /password:%s /cmd:securenatenable",
			g_vpncmdPath, hubName, gAdminPass);
		systemNice(toExec);
		sprintf(toExec, "\"%s\" /server localhost /hub:%s /password:%s /cmd:dhcpenable",
			g_vpncmdPath, hubName, gAdminPass);
		systemNice(toExec);
		sprintf(toExec, "\"%s\" /server localhost /hub:%s /password:%s /cmd:dhcpset /START:%s.2 /END:%s.254 /MASK:255.255.255.0 /EXPIRE:7200 /GW:%s.1 /DNS:8.8.8.8 /DNS2:none /DOMAIN:none /LOG:yes",
			g_vpncmdPath, hubName, gAdminPass, gTapBaseIP, gTapBaseIP, gTapBaseIP);
		systemNice(toExec);
	}
	else
	{
		sprintf(toExec, "\"%s\" /server localhost /hub:%s /password:%s /cmd:securenatenable",
			g_vpncmdPath, hubName, gAdminPass);
		systemNice(toExec);
		sprintf(toExec, "\"%s\" /server localhost /hub:%s /password:%s /cmd:natdisable",
			g_vpncmdPath, hubName, gAdminPass);
		systemNice(toExec);
		sprintf(toExec, "\"%s\" /server localhost /hub:%s /password:%s /cmd:dhcpenable",
			g_vpncmdPath, hubName, gAdminPass);
		systemNice(toExec);
		sprintf(toExec, "\"%s\" /server localhost /hub:%s /password:%s /cmd:dhcpset /START:%s.2 /END:%s.254 /MASK:255.255.255.0 /EXPIRE:7200 /GW:%s.1 /DNS:8.8.8.8 /DNS2:none /DOMAIN:none /LOG:yes",
			g_vpncmdPath, hubName, gAdminPass, gTapBaseIP, gTapBaseIP, gTapBaseIP);
		systemNice(toExec);
	}
}



StringLL* getExistingUsers()
{
	BOOL anyoneThere = FALSE;
	StringLL* existingUsersHead = newStringLL();
	StringLL* curExistTail = existingUsersHead;
	curExistTail->next = 0;

	char toExec[EXEC_VPNCMD_BUFSIZE];
	sprintf(toExec, "\"%s\" /server localhost /hub:salmon /password:%s /cmd userlist", g_vpncmdPath, gAdminPass);

	PIPEFILE* userLister = popenRNice(toExec);
	if(!userLister)
	{
		logError("Could not run userlist on SoftEther.");
		return 0;
	}

	size_t lineGetterLen = 200;
	char* lineGetter = malloc(lineGetterLen);
	memset(lineGetter, 0, lineGetterLen);
	while(getlinePipe(&lineGetter, &lineGetterLen, userLister) > 0)
		if(strstr(lineGetter, "User Name") && strchr(lineGetter, '|'))
		{
			anyoneThere = TRUE;
			//format: User Name      ...       |theusername
			char* nameStart = strchr(lineGetter, '|')+1;
			if (strchr(nameStart, '\n'))
				*strchr(nameStart, '\n') = 0;
			curExistTail = StringLL_add(curExistTail, nameStart);
		}
	
	pcloseNice(userLister);
	free(lineGetter);

	if(!anyoneThere)
	{
		StringLL_free(existingUsersHead);
		return 0;
	}

	return existingUsersHead;
}

void setAcceptedCredentials(const char* credBuf)
{
	//NOTE max email address length is 254, so this should be enough
	StringLL* newUsersHead = newStringLL();
	StringLL* newPassHead = newStringLL();
	StringLL* curUsersTail = newUsersHead;
	StringLL* curPassTail = newPassHead;

	char* credBufCopy = strdup(credBuf);//don't strtok an unfamiliar string, it could be a constant!

	//construct our received list of user credentials from the raw string
	char* cUsr = strtok(credBufCopy, "\n");
	if (!cUsr)
	{
		StringLL_free(newUsersHead);
		StringLL_free(newPassHead);
		free(credBufCopy);
		return;
	}
	char* cP = strtok(0, "\n");
	if (!cP)
	{
		StringLL_free(newUsersHead);
		StringLL_free(newPassHead);
		free(credBufCopy);
		return;//minor error
	}
	//NOTE: 	we could be interpreting the above cases (no identities listed) as meaning "wipe out
	//		everyone". however, in case there was just some hiccup, i wouldn't want to mess things
	//		up like that. so, if we really did want to tell a server to revoke everyone's access,
	//		we will instead just send them a single dummy account here.

	while (cUsr && cP)
	{
		curUsersTail = StringLL_add(curUsersTail, cUsr);
		curPassTail = StringLL_add(curPassTail, cP);
		cUsr = strtok(0, "\n");
		cP = strtok(0, "\n");
	}

	//if this is the first time this function has been called, hub "salmon" won't exist. if that's the case, create it now.
	//(ensureHub also ensures that DHCP is on, and configures whichever NAT is being used.)
	ensureHub("salmon");

	char toExec[EXEC_VPNCMD_BUFSIZE];

	//regardless of whether the hub needed to be created, ensure that softether's ipsec setting is on.
	//NOTE: ipsecenable is server-wide, so don't specify a hub!
	sprintf(toExec, "\"%s\" /server localhost /password:%s /cmd:ipsecenable /L2TP:yes /L2TPRAW:no /ETHERIP:no /PSK:%s /DEFAULTHUB:salmon", g_vpncmdPath, gAdminPass, gMyPSK);
	systemNice(toExec);

	//get the list of users we currently accept.
	StringLL* existingUsersHead = getExistingUsers();
	//NOTE: don't need to check for null; it would return null if no one exists, and that's fine.

	curUsersTail->next = 0;
	curPassTail->next = 0;

	//now, check if any users in our newly received list aren't already configured to be accepted: add them.
	StringLL* curUsers = newUsersHead;
	StringLL* curPass = newPassHead;
	StringLL* curExist;
	while (curUsers && curUsers->str)
	{
		if (!StringLL_contains(existingUsersHead, curUsers->str))
		{
			sprintf(toExec, "\"%s\" /server localhost /hub:salmon /password:%s /cmd groupcreate salmongroup /realname:none /note:none", g_vpncmdPath, gAdminPass);
			systemNice(toExec);
			sprintf(toExec, "\"%s\" /server localhost /hub:salmon /password:%s /cmd usercreate %s /group:salmongroup /realname:none /note:none", g_vpncmdPath, gAdminPass, curUsers->str);
			systemNice(toExec);

			///Again, softether's async nature is a problem here... in some (not all) test runs, the
			//client fails to connect until you manually set the pw on both the server and client - 
			//I'm pretty sure that system() returns before usercreate "takes effect", and then
			//userpasswordset fails (no user to set). (The crazy scrambled username is the same on both;
			//the pw gets derived in the same way, so there's no way it's a problem with that). 
			//Considering that even with no separation between them it was working more often than not, 
			//just sleep(1) alone would probably be ok, but let's do it the truly correct way.
			StringLL* checkForNewUser = 0;
			while (!StringLL_contains((checkForNewUser = getExistingUsers()), curUsers->str))
			{
				Sleep(500);
				StringLL_free(checkForNewUser);
			}
			StringLL_free(checkForNewUser);

			sprintf(toExec, "\"%s\" /server localhost /hub:salmon /password:%s /cmd userpasswordset %s /password:%s", g_vpncmdPath, gAdminPass, curUsers->str, curPass->str);
			systemNice(toExec);
		}
		curUsers = curUsers->next;
		curPass = curPass->next;
	}

	//finally, check if any currently accepted users aren't mentioned in the received list: remove them.
	curExist = existingUsersHead;
	while (curExist && curExist->str)
	{
		if (!StringLL_contains(newUsersHead, curExist->str))
		{
			sprintf(toExec, "\"%s\" /server localhost /hub:salmon /password:%s /cmd userdelete %s", g_vpncmdPath, gAdminPass, curExist->str);
			systemNice(toExec);
		}
		curExist = curExist->next;
	}

	//at this point, the first two are guaranteed to have been allocated, and ok to freeStringLL on.
	//however, existingUsersHead will be null if there weren't any users at the start of the functions,
	//but there WERE some we were asked to add.
	StringLL_free(newUsersHead);
	StringLL_free(newPassHead);
	if (existingUsersHead)
		StringLL_free(existingUsersHead);
	free(credBufCopy);
}


//Set the bandwidth limit for all users. The GroupPolicySet way of doing it avoids having to set it
//user-by-user, but it's unfortunately still just a per-user cap, enforced independently for each user.
void applyRateLimit(unsigned int kilobytes_per_sec)
{
	unsigned int bits_per_sec_BW = kilobytes_per_sec * 8 * 1000;

	char toExec[EXEC_VPNCMD_BUFSIZE];

	sprintf(toExec, "\"%s\" /server localhost /hub:salmon /password:%s /cmd grouppolicyset salmongroup /NAME:MaxDownload /VALUE:%u", g_vpncmdPath, gAdminPass, bits_per_sec_BW);
	systemNice(toExec);
	sprintf(toExec, "\"%s\" /server localhost /hub:salmon /password:%s /cmd grouppolicyset salmongroup /NAME:MaxUpload /VALUE:%u", g_vpncmdPath, gAdminPass, bits_per_sec_BW);
	systemNice(toExec);
}


//verify that userAccount is an account in our softether salmon hub
BOOL verifyUserAccount(const char* userAccount)
{
	char toExec[EXEC_VPNCMD_BUFSIZE];
	sprintf(toExec, "\"%s\" /server localhost /hub:salmon /password:%s /cmd userlist", g_vpncmdPath, gAdminPass);
	PIPEFILE* userLister = popenRNice(toExec);
	if (!userLister)
	{
		logError("Could not run userlist on the 'salmon' hub of SoftEther.");
		return FALSE;
	}
	size_t lineGetterLen = 200;
	char* lineGetter = malloc(lineGetterLen);
	memset(lineGetter, 0, lineGetterLen);
	BOOL accountIsThere = FALSE;
	while (getlinePipe(&lineGetter, &lineGetterLen, userLister) > 0)
	{
		if (strstr(lineGetter, userAccount))
		{
			accountIsThere = TRUE;
			break;
		}
	}
	pcloseNice(userLister);
	free(lineGetter);

	return accountIsThere;
}


void stripCommas(char* str)
{
	char* temp = (char*)malloc(strlen(str) + 1);
	memset(temp, 0, strlen(str) + 1);

	int i = 0, j = 0;
	for (i = 0; i < strlen(str); i++)
		if (str[i] >= '0' && str[i] <= '9')
		{
		temp[j] = str[i];
		j++;
		}

	strcpy(str, temp);
	free(temp);
}

//serverstatusget (NO HUB)
//output:
//Number of Sessions          |123
//Outgoing Unicast Total Size                   |269,047,484 bytes
//Incoming Unicast Total Size                   |290,521,227 bytes
//NOTE: incoming/outgoing appear to be largely the same. (that is, any discrepancy between them is not changed when user DLs 100MB.)
void parseServerStatus(char* serverStatusGetBuf, long long int* curTotalBytes, int* curUsers)
{
	char* numSessions = strstr(serverStatusGetBuf, "Number of Sessions");
	char* outgoingBytes = strstr(serverStatusGetBuf, "Outgoing Unicast Total Size");
	if (!numSessions || !strchr(numSessions, '|'))
		exitError("Malformed output from SoftEther's serverstatusget: 'Number of Sessions' missing.");
	
	if (!outgoingBytes || !strchr(outgoingBytes, '|'))
		exitError("Malformed output from SoftEther's serverstatusget: 'Outgoing Unicast Total Size' missing.");

	char tempSessions[100];
	strncpy(tempSessions, strchr(numSessions, '|') + 1, 99); tempSessions[99] = 0;
	if (strchr(tempSessions, '\n'))
		*strchr(tempSessions, '\n') = 0;
	stripCommas(tempSessions);
	*curUsers = atoi(tempSessions);

	char tempBytes[200];
	strncpy(tempBytes, strchr(outgoingBytes, '|') + 1, 199); tempBytes[199] = 0;
	if (strchr(tempBytes, '\n'))
		*strchr(tempBytes, '\n') = 0;
	stripCommas(tempBytes);
	*curTotalBytes = atoll(tempBytes);
}

void updateTooltip(int curBWUsed, int numUsersConnected);


/*
 * Ugh... here would be a perfectly fine crude workaround to turn SoftEther's per-user rate limiting
 * into server-wide rate limiting. Except, when you update the rate, it doesn't affect already-connected
 * users, i.e. the ones you're most interesting in changing the limit on. Maybe someday I can add
 * that to SoftEther itself (or, more likely, just add real server-wide rate limiting).
//(BE SURE TO LAUNCH THE THREAD AFTER g_vpncmdPath and gAdminPass and gOfferedBW HAVE BEEN FILLED)
DWORD WINAPI monitorUsersBandwidth(LPVOID dummyarg)
{
	char execStatusGet[EXEC_VPNCMD_BUFSIZE];
	char serverStatusGetBuf[4096];
	sprintf(execStatusGet, "\"%s\" /server localhost /password:%s /cmd serverstatusget", g_vpncmdPath, gAdminPass);

	long long int curTotalBytes = 0;
	long long int newTotalBytes = 0;
	int curUsers = 0;

	//units: bytes / second
	float realTotalOfferedBW = (float)atoi(gOfferedBW)*1000.0f; //gOfferedBW is in KBps
	float curPerUserBW = realTotalOfferedBW;

	//load initial values, so the first iteration doesn't see a huge jump in bytes from 0
	__int64 periodStart = getHNSecsNow();
	popenOneShotR(execStatusGet, serverStatusGetBuf, 4096);
	parseServerStatus(serverStatusGetBuf, &curTotalBytes, &curUsers);
	Sleep(10 * 1000);

	while (1)
	{
		popenOneShotR(execStatusGet, serverStatusGetBuf, 4096);
		//periodLen should be in seconds, and we're coming from hundreds of nanosecs.
		float periodLen = (float)(getHNSecsNow() - periodStart) / (float)(10LL * 1000LL * 1000LL);
		periodStart = getHNSecsNow();
		parseServerStatus(serverStatusGetBuf, &newTotalBytes, &curUsers);

		if (curUsers <= 0)
			goto JustRecordAndSleep;

		//if usage over the last 10 seconds was > 120% of offeredBW
		//    cut everyone's rate limit in half (but don't go below 20KBps)
		//else if <75% of offeredBW AND there might be someone limited (bw used > significant fraction of 1 person's share; i'm using 65%)
		//    scale all rates to what ought to use 100% of offeredBW
		//    (i.e. 10sec traffic observed/allowed = rate assigned/desired;
		//    rate desired = (rate assigned X 10sec traffic allowed) / 10sec traffic observed
		float lastPeriodBW = (curUsers <= 0 ? 0 : (float)(newTotalBytes - curTotalBytes) / periodLen);

		if (lastPeriodBW > 1.2f * realTotalOfferedBW)
		{
			curPerUserBW /= 2.0f;
			if (curPerUserBW < 20.0f)
				curPerUserBW = 20.0f;

			//curPerUserBW is in bytes/sec, applyRateLimit wants kilobytes/sec
			applyRateLimit((int)(curPerUserBW / 1000.0f));
		}
		else if (lastPeriodBW < 0.75f * realTotalOfferedBW     &&    lastPeriodBW >= 0.65f * curPerUserBW)
		{
			long long int allowedBytesPeriod = (long long int)(realTotalOfferedBW*periodLen);
			long long int observedBytesPeriod = newTotalBytes - curTotalBytes;

			curPerUserBW = (curPerUserBW * allowedBytesPeriod) / (float)observedBytesPeriod;
			if (curPerUserBW > realTotalOfferedBW)
				curPerUserBW = realTotalOfferedBW;

			//curPerUserBW is in bytes/sec, applyRateLimit wants kilobytes/sec
			applyRateLimit((int)(curPerUserBW / 1000.0f));
		}

	JustRecordAndSleep:
		curTotalBytes = newTotalBytes;
		updateTooltip((int)(lastPeriodBW / 1000.0f), curUsers);
		Sleep(10 * 1000);
	}
	return 0;
}

*/

//Even cruder workaround for the fact that SoftEther and Windows < 8.1 provide no way to
//limit the overall bandwidth used by the whole server. Every user (max of 4 simultaneous)
//gets 50% of the target bandwidth. We'll ask Windows volunteers to volunteer at least 150 KBps.
DWORD WINAPI monitorUsersBandwidth(LPVOID dummyarg)
{
	char execStatusGet[EXEC_VPNCMD_BUFSIZE];
	char serverStatusGetBuf[4096];
	sprintf(execStatusGet, "\"%s\" /server localhost /password:%s /cmd serverstatusget", g_vpncmdPath, gAdminPass);

	long long int curTotalBytes = 0;
	long long int newTotalBytes = 0;
	int curUsers = 0;

	//units: KBps
	float targetBandwidthBytes = (float)atoi(gOfferedBW);
	applyRateLimit((int)(targetBandwidthBytes*0.5f));

	//load initial values, so the first iteration doesn't see a huge jump in bytes from 0
	__int64 periodStart = getHNSecsNow();
	popenOneShotR(execStatusGet, serverStatusGetBuf, 4096);
	parseServerStatus(serverStatusGetBuf, &curTotalBytes, &curUsers);
	Sleep(10 * 1000);

	while (1)
	{
		popenOneShotR(execStatusGet, serverStatusGetBuf, 4096);
		//periodLen should be in seconds, and we're coming from hundreds of nanosecs.
		float periodLen = (float)(getHNSecsNow() - periodStart) / (float)(10LL * 1000LL * 1000LL);
		periodStart = getHNSecsNow();

		parseServerStatus(serverStatusGetBuf, &newTotalBytes, &curUsers);

		if (curUsers >= 4)
			gLastHad4Users = time(0);

		float lastPeriodBW = (float)(newTotalBytes - curTotalBytes) / periodLen;

		curTotalBytes = newTotalBytes;
		updateTooltip(curUsers <= 0 ? 0 : (int)(lastPeriodBW / 1000.0f), curUsers);
		Sleep(10 * 1000);
	}
	return 0;
}







//ensures access control rules (only http(s) etc are allowed) have been applied; applies if not
void ensurePortBlocks(char* hubName)
{
	char toExec[EXEC_VPNCMD_BUFSIZE];
	sprintf(toExec, "\"%s\" /server localhost /hub:%s /password:%s /cmd accesslist",
		   g_vpncmdPath, hubName, gAdminPass);
	PIPEFILE* accessLister = popenRNice(toExec);
	if(!accessLister)
	{
		logError("Could not run accesslist on SoftEther.");
		return;
	}

	size_t lineGetterLen = 200;
	char* lineGetter = malloc(lineGetterLen);
	memset(lineGetter, 0, lineGetterLen);
	while(getlinePipe(&lineGetter, &lineGetterLen, accessLister) > 0)
	{
		if(strstr(lineGetter, "zzzsalmondefaultdropzzz"))
		{
			pcloseNice(accessLister);
			free(lineGetter);
			return;
		}
	}
	pcloseNice(accessLister);
	free(lineGetter);
	
	
	//
	//If we reach here, the zzzsalmondefaultdropzzz rule isn't present; we assume they all need to be added.
	//
	
	
	//NOTE Lower number = higher priority. I have set HTTP(S) and DNS to be higher priority than the
	//rest: having the most popular rules at the top of the list ought to be more efficient.
	sprintf(toExec, "\"%s\" /server  localhost /hub:%s /password:%s /cmd accessadd pass /memo:dns /priority:1 /srcip:%s.0/24 /protocol:0 /destport:53 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				g_vpncmdPath, hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "\"%s\" /server  localhost /hub:%s /password:%s /cmd accessadd pass /memo:http /priority:1 /srcip:%s.0/24 /protocol:tcp /destport:80 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				g_vpncmdPath, hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "\"%s\" /server  localhost /hub:%s /password:%s /cmd accessadd pass /memo:https /priority:1 /srcip:%s.0/24 /protocol:tcp /destport:443 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				g_vpncmdPath, hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	Sleep(1000); //softether vpncmd appears to be finnicky about adding so many rules at once
	
	
	
	
	sprintf(toExec, "\"%s\" /server  localhost /hub:%s /password:%s /cmd accessadd pass /memo:ftpssh /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:20-22 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				g_vpncmdPath, hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "\"%s\" /server  localhost /hub:%s /password:%s /cmd accessadd pass /memo:kerberos /priority:2 /srcip:%s.0/24 /protocol:0 /destport:88 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				g_vpncmdPath, hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	Sleep(1000); //softether vpncmd appears to be finnicky about adding so many rules at once
	
	
	
	sprintf(toExec, "\"%s\" /server  localhost /hub:%s /password:%s /cmd accessadd pass /memo:viber /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:5242 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				g_vpncmdPath, hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "\"%s\" /server  localhost /hub:%s /password:%s /cmd accessadd pass /memo:viber /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:4244 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				g_vpncmdPath, hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "\"%s\" /server  localhost /hub:%s /password:%s /cmd accessadd pass /memo:viber /priority:2 /srcip:%s.0/24 /protocol:udp /destport:5243 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				g_vpncmdPath, hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	Sleep(1000); //softether vpncmd appears to be finnicky about adding so many rules at once
	
	sprintf(toExec, "\"%s\" /server  localhost /hub:%s /password:%s /cmd accessadd pass /memo:viber /priority:2 /srcip:%s.0/24 /protocol:udp /destport:9785 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				g_vpncmdPath, hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "\"%s\" /server  localhost /hub:%s /password:%s /cmd accessadd pass /memo:yahoomessenger /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:5050 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				g_vpncmdPath, hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "\"%s\" /server  localhost /hub:%s /password:%s /cmd accessadd pass /memo:aim /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:5190 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				g_vpncmdPath, hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	Sleep(1000); //softether vpncmd appears to be finnicky about adding so many rules at once
	
	sprintf(toExec, "\"%s\" /server  localhost /hub:%s /password:%s /cmd accessadd pass /memo:xmpp /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:5222-5223 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				g_vpncmdPath, hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "\"%s\" /server  localhost /hub:%s /password:%s /cmd accessadd pass /memo:httpalt /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:8008 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				g_vpncmdPath, hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "\"%s\" /server  localhost /hub:%s /password:%s /cmd accessadd pass /memo:httpalt /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:8080 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				g_vpncmdPath, hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	Sleep(2000); //softether vpncmd appears to be finnicky about adding so many rules at once
	
	
	
	
	sprintf(toExec, "\"%s\" /server  localhost /hub:%s /password:%s /cmd accessadd discard /memo:zzzsalmondefaultdropzzz /priority:3 /srcip:%s.0/24 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /destport: /srcport: /tcpstate: /protocol:0",
				g_vpncmdPath, hubName, gAdminPass, gTapBaseIP);
	system(toExec);
}

