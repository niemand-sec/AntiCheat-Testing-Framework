# DriverDisabler

## Introduction


## Usage

This Module will inject a "return" on the methods StartServiceA and OpenServiceW in order to prevent to the anti-cheat to load the driver.

## Configuration

This module does not requires much configuration, compile for the required architecture (x86/x64) and inject it.

It is possible to add new methods to test by adding them at  **handleAction**.

## Combination with other techniques

- Run this before the Anti-cheat is loaded completely. 
