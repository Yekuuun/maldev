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

base code samples &amp; usefull code snippets i wrote during maldev academy learning path.

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

**GetFuncAddress**
- `GetModuleHandleW` : Get address of loaded module in memory
- `GetProcAddress` : Retrieve address of function in a loaded module

**Shellcode Injections**
- `BaseInject` : Base shellcode injection using classic WinAPI functions (x64 payload)
- `NTInject` : Base shellcode injection using NTAPI (x64 payload)

---

### Notes : 

Do not pay attention to code property (shared functions etc.) I only used a utils.h file for <windows.h> & base payloads usage. I've planned to create a base lib with utility functions later.


---

### Thanks to : 

<strong><a href="https://github.com/orgs/Maldev-Academy/repositories">Maldev Academy</a></strong>
