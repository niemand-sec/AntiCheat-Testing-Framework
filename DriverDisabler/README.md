# DriverDisabler

## Introduction


## Usage

This Module will inject a "return" on the methods StartServiceA and OpenServiceW in order to prevent to the anti-cheat to load the driver.

Some Anti-Cheat (AC) load their service/driver from within the game. By injecting a return the method will get executed but no service will be started.

This module can be easily adapted to disable AC services that are started by using different methods.

## Configuration

This module does not requires much configuration, compile for the required architecture (x86/x64) and inject it.

**targetProc** need to be provided by usign config.ini file.

## Combination with other techniques

- Run this before the Anti-cheat is loaded completely. 
