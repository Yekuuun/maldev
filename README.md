```C
                     _____ ______   ________  ___       ________  _______   ___      ___ 
                    |\   _ \  _   \|\   __  \|\  \     |\   ___ \|\  ___ \ |\  \    /  /|
                    \ \  \\\__\ \  \ \  \|\  \ \  \    \ \  \_|\ \ \   __/|\ \  \  /  / /
                     \ \  \\|__| \  \ \   __  \ \  \    \ \  \ \\ \ \  \_|/_\ \  \/  / / 
                      \ \  \    \ \  \ \  \ \  \ \  \____\ \  \_\\ \ \  \_|\ \ \    / /  
                       \ \__\    \ \__\ \__\ \__\ \_______\ \_______\ \_______\ \__/ /   
                        \|__|     \|__|\|__|\|__|\|_______|\|_______|\|_______|\|__|/    
                                                                                         
                                -------base code samples for malware dev------   

```

> [!Important]
This repository was created due to my interest for malware development. I consider myself as a beginner and you may be surprised for some code samples. some code are duplicated in single cases such for payload encryption. The purpose is to speak about several subjects I dive into with maldev academy learning ressources -> <a href="https://github.com/Maldev-Academy">Maldev academy</a>


## You'll find : 

### Utils : 

- `PrintHex` : Printing hex data clean
- `String` : base & usefull string manipulation functions

### Maldev : 

**Payload Encryption**
- `XOR`
- `Rc4 (base)`
- `Rc4 (using SystemFunc032)`
- `ChaCha20`

**Obfuscation**
- `Ipv4 obfuscation` : Obfuscate payload using ipv4 formats + deobfuscation
- `String hashing` : Base hashing techniques for strings.

**Shellcode Injections**
- `BaseInject` : Base shellcode injection using classic WinAPI functions (x64 payload)
- `NTInject` : Base shellcode injection using NTAPI (x64 payload)

**Thread Hijacking**
- `LocalHijack` : Base locale thread hijacking (x64 calc payload)
- `RemoteHijack` : Base thread hijacking using SUSPENDED_PROCESS (x64 payload)

**APC Injection**
- `Local APC Inject` : Base APC injection in current running process (x64 payload)
- `Early Bird APC Inject` : Base remote APC injection (target process with x64 payload)

**Mapping Injection**
- `Local mapping injection` : Base payload injection using local mapping method (x64 payload)
- `Remote mapping injection` : Base remote mapping injection with x64 payload (using MapViewOfFile3)

**Spoofing**
- `PPid spoofing` : Base PPid spoofing (POC) spoof other process PID for new process creation

**PE**
- `Parser` : Base code sample for how to parse a PE file & display informations about it.

**Custom WINAPI**
- `GetModuleHandleW` : Custom implementation of GetModuleHandleW( ) - no imports
- `GetProcAddress` : Custom implementation of GetProcAddress( ) - no imports

> [!Note]
> Consider using hashing techniques inside of GetProcAddress avoiding usage of raw strings params in custom GetModuleHandleW & GetProcAddress calls by using hash comparison method

<br>

**Anti Debug**
- `BeingDebugged` : Base functions & logic to detect if current process is being debugged.
- `SelfDeleting` : Base code sample showing current process running deletion.

**NTDLL Unhooking**
- `FromDisk` : Base implementationg of NTDLL Unhooking from disk.

---

### Thanks to : 

- <strong><a href="https://github.com/orgs/Maldev-Academy/repositories">Maldev Academy</a></strong>
- <strong><a href="https://github.com/hasherezade">Hasherezade</a></strong>

---

> [!Warning]
> This repository was made for learning purpose.
