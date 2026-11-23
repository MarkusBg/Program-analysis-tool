import math
from collections import Counter

suspicious_apis = {
    "PE_Windows": {
        # Process Injection
        "OpenProcess": "Obtains a handle (access) to another process",
        "VirtualAllocEx": "Allocates memory in the address space of a remote process",
        "WriteProcessMemory": "Writes data (shellcode or a DLL) into another process's memory",
        "CreateRemoteThread": "Creates and starts a thread in another process's address space",
        "NtCreateThreadEx": "Low-level creation of a thread in a remote process (hook evasion)",
        "QueueUserAPC": "Queues an asynchronous procedure call (APC) to a thread to execute code",

        # Persistence and Privilege Escalation
        "RegOpenKeyEx": "Opens a registry key (often to look for autorun entries)",
        "RegSetValueEx": "Writes data to the registry (persistence via autorun)",
        "OpenSCManager": "Connects to the Windows Service Control Manager",
        "CreateService": "Creates a new system service for persistence",
        "StartService": "Starts a newly created or modified service",
        "OpenProcessToken": "Opens the access token associated with a process",
        "LookupPrivilegeValue": "Looks up the locally unique identifier (LUID) of a privilege",
        "AdjustTokenPrivileges": "Enables or disables privileges in an access token (e.g. SeDebugPrivilege)",

        # Defense Evasion and Anti-Debugging
        "IsDebuggerPresent": "Checks whether the current process is running under a debugger",
        "CheckRemoteDebuggerPresent": "Checks whether the process is being debugged by an external debugger",
        "NtQueryInformationProcess": "Retrieves system information about a process (looking for debugger traces)",
        "VirtualProtect": "Changes memory protection (e.g. to read/write/execute - RWX)",
        "LoadLibrary": "Loads a DLL dynamically at runtime",
        "GetProcAddress": "Retrieves a function address from a loaded DLL (import hiding)",

        # Data Collection, Spying and Encryption
        "SetWindowsHookEx": "Installs a hook on OS events, e.g. keystrokes",
        "GetAsyncKeyState": "Gets a key's state at the moment of the call (keylogging)",
        "GetKeyState": "Gets the pressed state of a virtual key",
        "InternetOpen": "Initializes WinINet functions for network access",
        "InternetConnect": "Opens an FTP or HTTP session to talk to a command-and-control (C2) server",
        "HttpSendRequest": "Sends an HTTP request to a remote server",
        "WSAStartup": "Initializes the Windows Sockets library (Winsock)",
        "connect": "Establishes a network connection to a remote host",
        "CryptAcquireContext": "Acquires a handle to a cryptographic service provider (CSP)",
        "CryptGenKey": "Generates a random cryptographic key (used by ransomware)",
        "CryptEncrypt": "Encrypts data (victim's files)",
        "FindFirstFile": "Finds the first file in a directory matching a pattern",
        "FindNextFile": "Continues enumerating files in a directory",

        # Command Execution and Process Creation
        "CreateProcess": "Creates a new process and its primary thread",
        "ShellExecute": "Performs an operation on a file (runs programs, scripts, commands)",
        "WinExec": "Legacy function to run an application or command"
    },

    "ELF_Linux": {
        # Code Injection and Anti-Debugging
        "ptrace": "Controls another process's execution (code injection) or anti-debugging (PTRACE_TRACEME)",
        "mmap": "Maps files or devices into memory; allocates executable memory for shellcode",
        "process_vm_writev": "Writes data directly into another process's address space",
        "mprotect": "Changes memory protection (e.g. allowing code execution - PROT_EXEC)",
        "dlopen": "Loads a shared library (.so) dynamically at runtime",
        "dlsym": "Retrieves a symbol (function) address from a dynamically loaded library",

        # Persistence and Privilege Escalation
        "chmod": "Changes file permissions (e.g. setting the SUID bit)",
        "fchmod": "Changes permissions of an open file descriptor",
        "chown": "Changes a file's owner and group",
        "setuid": "Sets the process user ID (UID) (attempt to gain root)",
        "setgid": "Sets the process group ID (GID)",
        "memfd_create": "Creates an anonymous in-memory file for fileless execution",
        "fexecve": "Executes a file by its file descriptor (often paired with memfd_create)",

        # Data Collection and Networking
        "read": "Reads data from a file descriptor (incl. capturing input from /dev/input/event*)",
        "XNextEvent": "Gets the next event from the X server (keystroke capture in a graphical session)",
        "socket": "Creates a network communication endpoint (socket)",
        "connect": "Initiates a connection on a socket to a remote server (C2)",
        "send": "Sends data over an established network connection",
        "recv": "Receives data from a network connection",
        "opendir": "Opens a directory stream for enumerating files",
        "readdir": "Reads the next entry (file or folder) from an open directory",
        "getdents": "Low-level system call that lists the files in a directory",

        # Command Execution and Process Creation
        "fork": "Creates an exact copy (child process) of the current process",
        "vfork": "Creates a child process, blocking the parent until exec is called",
        "clone": "Creates a child process or thread with fine-grained control over shared resources",
        "execve": "Replaces the current process image with a new program (spawning /bin/sh)",
        "system": "Runs a system command through the shell (/bin/sh -c)"
    }
}



def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())

def analyze_common(binary, fmt):
    findings = []

    # 1. секции: энтропия
    for s in binary.sections:
        e = entropy(bytes(s.content))
        if e > 7.0:
            findings.append(("high", f"Section {s.name}: entropy {e:.2f} (Packaging/encryption?)"))

    # 2. импорты: выбираем таблицу по формату
    names = {f.name for f in binary.imported_functions}
    table = suspicious_apis["PE_Windows" if fmt == "PE" else "ELF_Linux"]

    for api, why in table.items():
        # в Windows у функций бывают суффиксы A и W
        candidates = {api, api + "A", api + "W"} if fmt == "PE" else {api}
        hit = candidates & names
        if hit:
            findings.append(("medium", f"Import {next(iter(hit))}: {why}"))

    # 3. мало импортов
    if len(names) < 5:
        findings.append(("medium", f"Всего {len(names)} imports (possibly a packager)"))

    return findings