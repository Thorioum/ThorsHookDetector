<p align="center"> A Windows CLI for detecting inline, IAT, and EAT function hooks in running processes </p>

---
# Usage
- Either build yourself with CMAKE, grab from releases, or grab from build artifacts
- Run with ``` ThorsHookDetector.exe -p <Process Name> ```
## Optional Arguments
- ``` -l / --loadlibs ```: Will attempt to load all modules in target process into local process with LoadLibrary. Allows for scanning of more modules
- ``` -d / --ignorediff ```: Will ignore and NOT skip modules scanner detects as most likely a different dll version (different version determined by different size or new functions)

# Post Analysis Commands
After the analyis completes, gathering hooks, these commands can be ran after to interact with the process

- ``` restore-inline <Module Name> <Function Name> ```: uses results from the inline hook analysis and restores the functions bytes back to the original
- ``` restore-inline-all (OPTIONAL)<Module Name> ```: uses results from ALL FUNCTIONS in the inline hook analysis (in specific module if specified) and restores the functions bytes back to the original
- ``` restore-iat <Module Name> <Module Name> <Function Name> ```: uses results from iat hook analysis to restore addresses in the IAT table back from the hooked function to the original
- ``` restore-iat-all ```: uses results from ALL FUNCTIONS in iat hook analysis to restore addresses in the IAT table back from the hooked function to the original
- ``` decompile <Relative Virtual Address> || <Module Name> <Function Name> ```: decompiles the function at the specified address

# Preview of program
![2025-05-16 00_01_57-Window](https://github.com/user-attachments/assets/8726f331-f972-4bba-84f8-3877249bf70e)
<img width="865" alt="0C997315-1434-4D8A-BE67-77C77E7D72EE" src="https://github.com/user-attachments/assets/92fdd051-d2fa-4d01-bc9c-ba5bfac7db12" />
