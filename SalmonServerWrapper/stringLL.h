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

#ifndef __STRINGLINKEDLIST_INCLGUARD__
#define __STRINGLINKEDLIST_INCLGUARD__

typedef struct StringLL
{
	char* str;
	struct StringLL* next;
} StringLL;

void StringLL_free(StringLL* toFree);
StringLL* newStringLL();
//returns newly created tail node; building a whole list with this function takes linear time if you keep calling it on the tail
StringLL* StringLL_add(StringLL* startNode, char* theString);
//checks strcmp(theString, [each node]). boolean: 0 = false
int StringLL_contains(StringLL* head, char* theString);

#endif //__STRINGLINKEDLIST_INCLGUARD__