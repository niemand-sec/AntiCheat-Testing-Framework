# HandleHijackingMaster

## Introduction


## Usage

This module is used combinaded with **HandleHijackingDLL**. This is the "command and control" implementation. Has to be executed before injecting the DLL. 

HandleHijakingMaster will create a NamedPipe that the DLL will use to receive instructions and then return information to the master (where all the bot logic should be located).

## Configuration

This module requries configuration:

- Address to Read/Write (TODO: implement to use multiple addresses, not just one)
- Sequence of actions to perform (TODO: now it tries everything from 0 to 5, implement a list)
- HANDLE to use as pivot (TODO: It is hardocded now so it need to be recompiled, it would be better to enumerate handles and identify the correct one).
- Buffer with the CONTENT we will write.
- CHANGE VALUE OF namedPipeName
 
## Combination with other techniques

- **RUNASKINVOKER**: By executing the game using this options we will prevent the Anti-cheat to fully protect the game end load the driver.


