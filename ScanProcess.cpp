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

bool create_new_process(PROCESS_INFORMATION &pi, const LPSTR cmdLine, LPCSTR startDir = NULL)
{
	STARTUPINFO si;
	memset(&si, 0, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));

	if (!CreateProcessA(
		NULL,
		cmdLine,
		NULL, //lpProcessAttributes
		NULL, //lpThreadAttributes
		FALSE, //bInheritHandles
		CREATE_NO_WINDOW, //dwCreationFlags
		NULL, //lpEnvironment 
		startDir, //lpCurrentDirectory
		&si, //lpStartupInfo
		&pi //lpProcessInformation
	))
	{
		return false;
	}
	return true;
}


scan_res ScanProcess(const char pesieve_dir[], int pid, const char out_dir[], bool is_remote)
{
	std::stringstream ss;
	ss << pesieve_dir;
	ss << "\\";
	ss << PE_SIEVE;
	ss << " /pid " << std::dec << pid;
	ss << " /dir " << out_dir;
	if (is_remote) {
		ss << " /shellc A";
	}
	else {
		ss << " /mignore ntdll.dll"; // NTDLL is patched by the Pin
	}
	ss << " /quiet";

	std::string cmdline = ss.str();
	PROCESS_INFORMATION pi = { 0 };
	if (!create_new_process(pi, (LPSTR)cmdline.c_str())) {
		return SCAN_ERROR_0;
	}
	DWORD code = 0;
	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &code);
	if (code == PESIEVE_NOT_DETECTED) {
		return SCAN_NOT_SUSPICIOUS;
	}
	if (code == PESIEVE_DETECTED) {
		return SCAN_SUSPICIOUS;
	}
	return SCAN_ERROR_1;
}
