# Various PWSH scripts

# Get Members - getmembers.ps1
This script gathers all members from a security group and their properties and exports them to a CSV file. Object metadata is gathered using repadmin.exe.

## Usage:
```
pwsh -ep bypass -f getmembers.ps1 -targetlist mytargets.txt -output 'C:\Users\MyUser\Documents\myoutput.csv'
```

# Bitlocker Remote Handler - encryption_handler.ps1
This tool uses PsExec and Dell Command and Configure to perform various operations on remote Dell systems involving TPM activation and Bitlocker encryption.

## Requirements

- [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec): The PsExec.exe file must be in the same location as the script otherwise specify the '-psexec' switch with a path to the executable.
- [Dell Command and Configure 3.3](https://www.dell.com/support/driver/en-us/DriversDetails?driverId=FVGF9): .EXE contents must be extracted and zipped in a file called 'dcc.zip' and placed in the script directory, otherwise specifiy the '-installfiles' switch with a path to the zipped files.

## Usage

```
-report         => Run installer in reporting mode. Will output system information about TPM
-encrypt        => Starts TPM and encryption operations
-target         => Specify target system
-biospass       => Specify BIOS password to use with operations
-psexec         => Path to PsExec.exe
-installfiles   => Path to installation files
```

## Examples

Run report on target system:
```
pwsh -ep bypass -f .\encryption_handler.ps1 -report -target 10.10.10.254
```
Enable TPM:
```
pwsh -executionpolicy bypass -f .\encryption_handler.ps1 -encrypt -biospass mybiospassword -target 10.10.10.254
```
