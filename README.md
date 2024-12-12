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
- `Ipv4 obfuscation` Obfuscate payload using ipv4 formats + deobfuscation

**GetFuncAddress**
- `GetModuleHandleW` : Get address of loaded module in memory
- `GetProcAddress` : Retrieve address of function in a loaded module

**Shellcode Injections**
- `BaseInject` : Base shellcode injection using classic WinAPI functions (x64 payload)
- `NTInject` : Base shellcode injection using NTAPI (x64 payload)

**Thread Hijacking**
- `LocalHijack` : Base locale thread hijacking (x64 calc payload)
- `RemoteHijack` : Base thread hijacking using SUSPENDED_PROCESS (x64 payload)

**Work in progress...** 🛠️

---

> [!Warning]
> This repository was made for learning purpose.

---

### Thanks to : 

- <strong><a href="https://github.com/orgs/Maldev-Academy/repositories">Maldev Academy</a></strong>
- <strong><a href="https://github.com/hasherezade">Hasherezade</a></strong>
