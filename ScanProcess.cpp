#include "ScanProcess.h"

#include "win/win_paths.h"
#include <pe_sieve_api.h>
#include <pe_sieve_return_codes.h>

#include <sstream>

#ifdef _WIN64
#define PE_SIEVE "pe-sieve64.exe"
#else
#define PE_SIEVE "pe-sieve32.exe"
#endif

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
