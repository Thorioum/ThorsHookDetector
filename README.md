<p align="center"> A Windows CLI for detecting inline, IAT, and EAT function hooks in running processes </p>

---
# Usage
- Either build yourself with CMAKE, or grab from releases
- Run with ``` ThorsHookDetector.exe -p <PROCESS_NAME> ```
## Optional Arguments
- ``` -l / --loadlibs ```: Will attempt to load all modules in target process into local process with LoadLibrary. Allows for scanning of more modules
- ``` -d / --ignorediff ```: Will ignore and NOT skip modules scanner detects as most likely a different dll version (different version determined by different size or new functions)
  
