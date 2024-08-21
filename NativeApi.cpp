#include "NativeApi.h"

#include "win/win_paths.h"
#include <sstream>


int getPidByThreadHndl(void* hndl)
{
	HANDLE phndl = (HANDLE)hndl;
	DWORD pid = GetProcessIdOfThread(phndl);
	return pid;
}

int getPidByProcessHndl(void *hndl)
{
	HANDLE phndl = (HANDLE)hndl;
	DWORD pid = GetProcessId(phndl);
	return pid;
}
