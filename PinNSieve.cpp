/*
* PinNSieve, CC by: hasherezade@gmail.com
* Runs with: Intel PIN (https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool)
*
* Prints to <output_file> addresses of transitions from one sections to another
* (helpful in finding OEP of packed file)
* args:
* -m    <module_name> ; Analysed module name (by default same as app name)
* -o    <output_path> Output file
*
*/

#include "pin.H"

#include <iostream>
#include <string>
#include <set>

#include "ProcessInfo.h"
#include "TraceLog.h"

#include "ScanProcess.h"

#define TOOL_NAME "Pin'n'Sieve"
#define VERSION "0.1.1"

#include "Util.h"
#include "Settings.h"


/* ================================================================== */
// Global variables 
/* ================================================================== */

Settings m_Settings;
std::string m_PESieveDir;
ProcessInfo pInfo;
TraceLog traceLog;


// last shellcode to which the transition got redirected:
std::set<ADDRINT> m_tracedShellc;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "", "Specify file name for the output");

KNOB<std::string> KnobIniFile(KNOB_MODE_WRITEONCE, "pintool",
    "s", "", "Specify the settings file");

KNOB<std::string> KnobPEsieveDir(KNOB_MODE_WRITEONCE, "pintool",
    "d", "", "Specify the PE-sieve DLLs directory");

KNOB<std::string> KnobModuleName(KNOB_MODE_WRITEONCE, "pintool",
    "m", "", "Analysed module name (by default same as app name)");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
*  Print out help message.
*/
INT32 Usage()
{
    std::cerr << "This tool prints out : " << std::endl <<
        "Addresses of redirections into to a new sections. Called API functions.\n" << std::endl;

    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

// compare strings, ignore case
bool isStrEqualI(const std::string &str1, const std::string &str2)
{
    if (str1.length() != str2.length()) {
        return false;
    }
    for (size_t i = 0; i < str1.length(); i++) {
        if (tolower(str1[i]) != tolower(str2[i])) {
            return false;
        }
    }
    return true;
}

/* ===================================================================== */
// PE-sieve deployment
/* ===================================================================== */


bool RunPEsieveScan(int pid)
{
    scan_res res = ScanProcess(m_PESieveDir.c_str(), pid, m_Settings.outDir.c_str());
    std::stringstream ss;
    ss << "Scanned by PE-sieve: ";
    ss << " PID: " << pid << ", ";
    ss << "Status: ";
    if (res == SCAN_SUSPICIOUS) {
        ss << "SUSPICIOUS, ";
        ss << "dumped to: \"" << m_Settings.outDir << "\"";
    }
    else if (res == SCAN_NOT_SUSPICIOUS) {
        ss << " NOT_SUSPICIOUS";
    }
    else {
        ss << " scan failed: " << std::dec << res;
    }
    traceLog.logLine(ss.str());
    return (res == SCAN_SUSPICIOUS) ? true : false;
}


/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

BOOL isTracedShellc(ADDRINT addr)
{
    if (m_tracedShellc.find(addr) != m_tracedShellc.end()) {
        return TRUE;
    }
    return FALSE;
}

VOID _SaveTransitions(const ADDRINT addrFrom, const ADDRINT addrTo)
{
    const bool isTargetMy = pInfo.isMyAddress(addrTo);
    const bool isCallerMy = pInfo.isMyAddress(addrFrom);

    IMG targetModule = IMG_FindByAddress(addrTo);
    IMG callerModule = IMG_FindByAddress(addrFrom);

    //is it a transition from the traced module to a foreign module?
    if (isCallerMy && !isTargetMy) {
        ADDRINT RvaFrom = addr_to_rva(addrFrom);
        if (!IMG_Valid(targetModule)) {
            //not in any of the mapped modules:
            const ADDRINT pageTo = query_region_base(addrTo);
            m_tracedShellc.insert(pageTo); //save the beginning of this area
            traceLog.logCall(0, RvaFrom, pageTo, addrTo);
            // scan current process:
            RunPEsieveScan(PIN_GetPid());
        }
    }
    // trace calls from witin a shellcode:
    if (!IMG_Valid(callerModule)) {

        const ADDRINT pageFrom = query_region_base(addrFrom);
        const ADDRINT callerPage = pageFrom;
        if (callerPage != UNKNOWN_ADDR) {

            if (isTracedShellc(callerPage))
            {
                const ADDRINT pageTo = query_region_base(addrTo);
                if (IMG_Valid(targetModule)) { // it is a call to a module

                    const std::string func = get_func_at(addrTo);
                    const std::string dll_name = IMG_Name(targetModule);
                    traceLog.logCall(callerPage, addrFrom, false, dll_name, func);
                }
                else if (pageFrom != pageTo) // it is a call to another shellcode
                {
                    // add the new shellcode to the set of traced
                    m_tracedShellc.insert(pageTo);

                    // scan on the transition from one shellcode to the other
                    ADDRINT base = get_base(addrFrom);
                    ADDRINT RvaFrom = addrFrom - base;
                    traceLog.logCall(base, RvaFrom, pageTo, addrTo);
                    // scan current process:
                    RunPEsieveScan(PIN_GetPid());
                }
            }
        }
    }

    // is the address within the traced module?
    if (isTargetMy) {
        ADDRINT rva = addr_to_rva(addrTo); // convert to RVA

        // is it a transition from one section to another?
        if (pInfo.updateTracedModuleSection(rva)) {
            const s_module* sec = pInfo.getSecByAddr(rva);
            std::string curr_name = (sec) ? sec->name : "?";
            if (isCallerMy) {

                ADDRINT rvaFrom = addr_to_rva(addrFrom); // convert to RVA
                const s_module* prev_sec = pInfo.getSecByAddr(rvaFrom);
                std::string prev_name = (prev_sec) ? prev_sec->name : "?";
                traceLog.logNewSectionCalled(rvaFrom, prev_name, curr_name);
            }
            traceLog.logSectionChange(rva, curr_name);
            // scan current process:
            RunPEsieveScan(PIN_GetPid()); //possibly an unpacked section
        }
    }
}

VOID SaveTransitions(const ADDRINT prevVA, const ADDRINT Address)
{
    PIN_LockClient();
    _SaveTransitions(prevVA, Address);
    PIN_UnlockClient();
}

VOID RdtscCalled(const CONTEXT* ctxt)
{
    PIN_LockClient();

    ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    IMG currModule = IMG_FindByAddress(Address);
    const bool isCurrMy = pInfo.isMyAddress(Address);
    if (isCurrMy) {
        ADDRINT rva = addr_to_rva(Address); // convert to RVA
        traceLog.logRdtsc(0, rva);
    }
    if (!IMG_Valid(currModule)) {
        const ADDRINT start = query_region_base(Address);
        ADDRINT rva = Address - start;
        if (start != UNKNOWN_ADDR) {
            traceLog.logRdtsc(start, rva);
        }
    }

    PIN_UnlockClient();
}

VOID CpuidCalled(const CONTEXT* ctxt)
{
    PIN_LockClient();

    ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    ADDRINT Param = (ADDRINT)PIN_GetContextReg(ctxt, REG_GAX);

    IMG currModule = IMG_FindByAddress(Address);
    const bool isCurrMy = pInfo.isMyAddress(Address);
    if (isCurrMy) {
        ADDRINT rva = addr_to_rva(Address); // convert to RVA
        traceLog.logCpuid(0, rva, Param);
    }
    if (!IMG_Valid(currModule)) {
        const ADDRINT start = query_region_base(Address);
        ADDRINT rva = Address - start;
        if (start != UNKNOWN_ADDR) {
            traceLog.logCpuid(start, rva, Param);
        }
    }

    PIN_UnlockClient();
}

ADDRINT _setTimer(const CONTEXT* ctxt, bool isEax)
{
    static UINT64 Timer = 0;
    UINT64 result = 0;

    if (Timer == 0) {
        ADDRINT edx = (ADDRINT)PIN_GetContextReg(ctxt, REG_GDX);
        ADDRINT eax = (ADDRINT)PIN_GetContextReg(ctxt, REG_GAX);
        Timer = (UINT64(edx) << 32) | eax;
    }
    else {
        Timer += 100;
    }

    if (isEax) {
        result = (Timer << 32) >> 32;
    }
    else {
        result = (Timer) >> 32;
    }
    return (ADDRINT)result;
}

ADDRINT AlterRdtscValueEdx(const CONTEXT* ctxt)
{
    ADDRINT result = 0;

    PIN_LockClient();
    result = _setTimer(ctxt, false);
    PIN_UnlockClient();

    return result;
}

ADDRINT AlterRdtscValueEax(const CONTEXT* ctxt)
{
    ADDRINT result = 0;

    PIN_LockClient();
    result = _setTimer(ctxt, true);
    PIN_UnlockClient();

    return result;
}

/* ===================================================================== */
// Instrument functions arguments
/* ===================================================================== */

bool isWatchedAddress(const ADDRINT Address)
{
    IMG currModule = IMG_FindByAddress(Address);
    const bool isCurrMy = pInfo.isMyAddress(Address);
    if (isCurrMy) {
        return true;
    }
    const BOOL isShellcode = !IMG_Valid(currModule);
    if (isShellcode) {
        /*if (m_Settings.followShellcode == SHELLC_FOLLOW_ANY) {
            return true;
        }*/
        const ADDRINT callerRegion = query_region_base(Address);
        // trace calls from the monitored shellcode only:
        if (callerRegion != UNKNOWN_ADDR && isTracedShellc(callerRegion)) {
            return true;
        }
    }
    return false;
}


VOID _WatchExistingThread(const ADDRINT Address, CHAR *name, VOID* threadId)
{
    int pid = getPidByThreadHndl(threadId);
    std::stringstream ss;
    ss << "Thread via: ";
    ss << name;
    ss << " threadID: " << threadId;
    ss << " PID: " << pid;
    traceLog.logLine(ss.str());

    RunPEsieveScan(pid);
}

VOID WatchExistingThread(const ADDRINT Address, CHAR *name, VOID* threadId)
{
    PIN_LockClient();
    _WatchExistingThread(Address, name, threadId);
    PIN_UnlockClient();
}

VOID MonitorExistingThread(IMG Image, CHAR* fName, int procHndlArgNum)
{
    RTN funcRtn = RTN_FindByName(Image, fName);
    if (!RTN_Valid(funcRtn)) return; // failed

    RTN_Open(funcRtn);

    RTN_InsertCall(funcRtn,
        IPOINT_BEFORE,
        AFUNPTR(WatchExistingThread),
        IARG_RETURN_IP,
        IARG_ADDRINT, fName,
        IARG_FUNCARG_ENTRYPOINT_VALUE, procHndlArgNum, //ThreadHandle
        IARG_END
    );

    RTN_Close(funcRtn);
}
//---

VOID _WatchCreateThread(const ADDRINT Address, CHAR *name, VOID* processHndl)
{
    int pid = getPidByProcessHndl(processHndl);
    std::stringstream ss;
    ss << "Thread via: ";
    ss << name;
    ss << " PID: " << pid << "\n";
    traceLog.logLine(ss.str());
    ss.clear();

    RunPEsieveScan(pid);
}

VOID WatchCreateThread(const ADDRINT Address, CHAR *name, VOID* threadId)
{
    PIN_LockClient();
    _WatchCreateThread(Address, name, threadId);
    PIN_UnlockClient();
}

VOID MonitorCreateThread(IMG Image, CHAR* fName, int procHndlArgNum)
{
    RTN funcRtn = RTN_FindByName(Image, fName);
    if (!RTN_Valid(funcRtn)) return; // failed

    RTN_Open(funcRtn);

    RTN_InsertCall(funcRtn,
        IPOINT_BEFORE,
        AFUNPTR(WatchCreateThread),
        IARG_RETURN_IP,
        IARG_ADDRINT, fName,
        IARG_FUNCARG_ENTRYPOINT_VALUE, procHndlArgNum, //ProcessHandle
        IARG_END
    );

    RTN_Close(funcRtn);
}

VOID MonitorThreads(IMG Image)
{
    MonitorExistingThread(Image, "NtResumeThread", 0);
    MonitorExistingThread(Image, "NtQueueApcThread", 0);
    MonitorExistingThread(Image, "NtQueueApcThreadEx", 0);
    MonitorExistingThread(Image, "NtAlertResumeThread", 0);

    MonitorCreateThread(Image, "NtCreateThreadEx", 3);
    MonitorCreateThread(Image, "NtCreateThread", 3);
    MonitorCreateThread(Image, "RtlCreateUserThread", 0);
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID InstrumentInstruction(INS ins, VOID *v)
{
    if (isStrEqualI(INS_Mnemonic(ins), "cpuid")) {
        INS_InsertCall(
            ins,
            IPOINT_BEFORE, (AFUNPTR)CpuidCalled,
            IARG_CONTEXT,
            IARG_END
        );
    }

    if (INS_IsRDTSC(ins)) {
        INS_InsertCall(
            ins,
            IPOINT_BEFORE, (AFUNPTR)RdtscCalled,
            IARG_CONTEXT,
            IARG_END
        );

        INS_InsertCall(
            ins, 
            IPOINT_AFTER, (AFUNPTR)AlterRdtscValueEdx,
            IARG_CONTEXT,
            IARG_RETURN_REGS, 
            REG_GDX,
            IARG_END);

        INS_InsertCall(ins, 
            IPOINT_AFTER, (AFUNPTR)AlterRdtscValueEax,
            IARG_CONTEXT,
            IARG_RETURN_REGS,
            REG_GAX,
            IARG_END);
    }

    if ((INS_IsControlFlow(ins) || INS_IsFarJump(ins))) {
        INS_InsertCall(
            ins, 
            IPOINT_BEFORE, (AFUNPTR)SaveTransitions,
            IARG_INST_PTR,
            IARG_BRANCH_TARGET_ADDR,
            IARG_END
        );
    }
}

VOID ImageLoad(IMG Image, VOID *v)
{
    PIN_LockClient();
    pInfo.addModule(Image);
    MonitorThreads(Image);
    PIN_UnlockClient();
}

//-----

static void OnCtxChange(THREADID threadIndex,
    CONTEXT_CHANGE_REASON reason,
    const CONTEXT *ctxtFrom,
    CONTEXT *ctxtTo,
    INT32 info,
    VOID *v)
{
    if (ctxtTo == NULL || ctxtFrom == NULL) return;

    PIN_LockClient();
    const ADDRINT addrFrom = (ADDRINT)PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
    const ADDRINT addrTo = (ADDRINT)PIN_GetContextReg(ctxtTo, REG_INST_PTR);
    _SaveTransitions(addrFrom, addrTo);
    PIN_UnlockClient();
}

/*!
* The main procedure of the tool.
* This function is called when the application image is loaded but not yet started.
* @param[in]   argc            total number of elements in the argv array
* @param[in]   argv            array of command line arguments,
*                              including pin -t <toolname> -- ...
*/

int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 

    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    std::string app_name = KnobModuleName.Value();
    if (app_name.length() == 0) {
        // init App Name:
        for (int i = 1; i < (argc - 1); i++) {
            if (strcmp(argv[i], "--") == 0) {
                app_name = argv[i + 1];
                break;
            }
        }
    }

    pInfo.init(app_name);

    m_PESieveDir = KnobPEsieveDir.ValueString();
    std::cout << "PE-sieve dir: " << m_PESieveDir << std::endl;

    const std::string iniFilename = KnobIniFile.ValueString();
    if (!m_Settings.loadINI(iniFilename)) {
        std::cerr << "Coud not load the INI file: " << iniFilename << std::endl;
        m_Settings.saveINI(iniFilename);
    }

    // init output file:
    traceLog.init(KnobOutputFile.Value(), true);

    // Register function to be called for every loaded module
    IMG_AddInstrumentFunction(ImageLoad, NULL);

    // Register function to be called before every instruction
    INS_AddInstrumentFunction(InstrumentInstruction, NULL);

    // Register context changes
    PIN_AddContextChangeFunction(OnCtxChange, NULL);
    
    std::cerr << "===============================================" << std::endl;
    std::cerr << "This application is instrumented by " << TOOL_NAME << " v." << VERSION << std::endl;
    std::cerr << "Tracing module: " << app_name << std::endl;
    if (!KnobOutputFile.Value().empty())
    {
        std::cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << std::endl;
    }
    std::cerr << "===============================================" << std::endl;

    // Start the program, never returns
    PIN_StartProgram();
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

