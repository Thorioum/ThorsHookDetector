<p align="center"> A Windows CLI for detecting inline, IAT, and EAT function hooks in running processes </p>

---
# Usage
- Either build yourself with CMAKE, or grab from releases
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
<img width="769" alt="BB2E8044-D671-4A21-B2E5-0241D047C423" src="https://github.com/user-attachments/assets/6cd2963a-9440-4a0d-b8bc-f860c17d925f" />
