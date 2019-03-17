# HandleHijacking DLL

## Introduction


## Usage

This module is used combinaded with **HandleHijackingMaster**. This is the DLL implementation that has to be injected into a process that already has a handle to the game.

HandleHijakingMaster will create a NamedPipe that this module uses to receive instructions and then return information to the master (where all the bot logic should be located).

## Combination with other techniques

- **RUNASKINVOKER**: By executing the game using this options we will prevent the Anti-cheat to fully protect the game end load the driver.


