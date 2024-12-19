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

**Payload Obfuscation**
- `Ipv4 obfuscation` Obfuscate payload using ipv4 formats + deobfuscation (base example on how to transform a payload into legit data)

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
- `GetModuleHandleW` : Custom implementation of GetModuleHandleW( ) function
- `GetProcAddress` : Custom implementation of GetProcAddress( ) function

**Work in progress...** 🛠️

---

> [!Warning]
> This repository was made for learning purpose.

---

### Thanks to : 

- <strong><a href="https://github.com/orgs/Maldev-Academy/repositories">Maldev Academy</a></strong>
- <strong><a href="https://github.com/hasherezade">Hasherezade</a></strong>
