<img src="Icon.png" align="right" alt="Image" height="80" width="80"/>

# ERC.Xdbg    
[![License](https://img.shields.io/github/license/Andy53/ERC.Xdbg)](license.txt)
[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/Andy53/ERC.Xdbg?style=flat)](https://github.com/Andy53/ERC.Xdbg/tags)
[![GitHub issues](https://img.shields.io/github/issues-raw/Andy53/ERC.Xdbg?style=flat)](https://github.com/Andy53/ERC.Xdbg/issues)
<a href="https://github.com/Andy53/ERC.Xdbg/commits/master">
    <img src="https://img.shields.io/github/last-commit/Andy53/ERC.Xdbg?style=flat-square&logo=github&logoColor=white">
</a>

An X64dbg Plugin of the [ERC](https://github.com/Andy53/ERC.net) Library.

## Installation
Installing the plugin is reasonably straight forward. Simply download the appropriate zip package for your architecture from the releases page of this repoistory and save then unzip it in the plugins directory of X64dbg. If X64dbg does not currently have a plugins directory then run it once to create the intial directory structure.

If you wish to build the plugin from source simply clone the Git repository, open the solution in Visual Studio and build the project targeted for your architecture of choice. Then copy the binaries into the plugins directory of your X64dbg installation.

## Documentation
This library contains the fundamental specifications, documentation, and architecture that underpin ERC.Xdbg. If you're looking to understand the system better, or want to know how to integrate the various components, there is a lot of valuable information contained here.    

[📄 Documentation and Specifications](https://andy53.github.io/ERC.net/)    

## API     
ERC.Net is the API used to develop ERC.Xdbg, all of the functionality in this plugin stems from the API. ERC.Net is a collection of tools designed to assist in debugging Windows application crashes.  
        
[📁 Source](https://github.com/Andy53/ERC.net) - https://github.com/Andy53/ERC.net     
[📦 32 bit Package - ERC.Net-x86.SDK](https://www.nuget.org/packages/ERC.Net-x86/)    
[📦 64 bit Package - ERC.Net-x64.SDK](https://www.nuget.org/packages/ERC.Net-x64/)   

## Articles    
A list of articles covering common usage scenarios using ERC.Xdbg.
    
[📄 The Basics of Exploit Development 1: Win32 Buffer Overflows](https://www.coalfire.com/The-Coalfire-Blog/January-2020/The-Basics-of-Exploit-Development-1) 

## Globals
Global variables are variables which are set and stored for one session. They are reset to the defaults each time X64dbg is restarted.     

`-ASLR`   
Used to exclude pointers from modules implementing ASLR in search output. Can be reset by supplying `false` as a parameter.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -ASLR` Remove pointers from ASLR enabled modules from all search results.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -ASLR false` Include pointers from ASLR enabled modules in all search results.    

`-SafeSEH`   
Used to exclude pointers from modules implementing SafeSEH in search output. Can be reset by supplying `false` as a parameter.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -SafeSEH` Remove pointers from SafeSEH enabled modules from all search results.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -SafeSEH false` Include pointers from SafeSEH enabled modules in all search results.    

`-Rebase`    
Used to exclude pointers from modules implementing Rebase in search output. Can be reset by supplying `false` as a parameter.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -Rebase` Remove pointers from Rebase enabled modules from all search results.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -Rebase false` Include pointers from Rebase enabled modules in all search results.    

`-NXCompat`    
Used to exclude pointers from modules implementing NXCompat in search output. Can be reset by supplying `false` as a parameter.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -NXCompat` Remove pointers from NXCompat enabled modules from all search results.   
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -NXCompat false` Include pointers from NXCompat enabled modules in all search results.    

`-OSdll`    
Used to exclude pointers from modules that are OSdll's in search output. Can be reset by supplying `false` as a parameter.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -OSdll` Remove pointers from OSdll's from all search results.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -OSdll false` Include pointers from OSdll's in all search results.    

`-Bytes`    
Used to exploit pointers containing specific bytes from all search results. Can be disabled by passing switch with no arguments. Bytes must be passed without spaces.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -Bytes 0x0A0x0D` Remove pointers containing bytes 0A or 0D from all search results.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -Bytes 740D` Remove pointers containing bytes 74 or 0D from all search results.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -Bytes` Remove any previous byte restrictions from all further search results.    

`-Protection`
Used to specify the protection value of all pointers returned in search results. Generic values of `read`, `write` and `exec` are used to specify which the returned pointers should have and can be used in combination. Options must be sperated with commas and no spaces.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -Protection exec` Remove pointers that do not have exec permission from all search results.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -Protection read,exec` Remove pointers that do not have read and exec permission from all search results.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help -Protection all` Remove any previous protection restrictions from all further search results.

## Usage
Instructions on usage of the plugin can be seen below. This can also be accessed directly through the debugger using `ERC --help`. 

Details on each command can be seen below. Commands are not case sensitive.

`--Help`       
Displays the help message below.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help`    

`--Update`
Downloads the latest release of the plugin from Github and extracts it into the X64Dbg plugin directory for the architecture currently in use. Can be passed a ip:port pair in order to specify a proxy.
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --update 127.0.0.1:8080`

`--config`    
The config option can be used to set values in the config.xml file. These options persist between sessions. Can be used to set things such as the project author, current working directory and error log file. These options are predominatly used when writing the output of operations to file.    
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --config SetWorkingDirectory C:\Users\You\Desktop`   
&nbsp;&nbsp;&nbsp;&nbsp;Example 2: `ERC --config GetErrorFilePath`

`--Pattern`   
The pattern option can be used to either create a pattern or to identify the location of a string within a pattern. Appending a c and then a number will create a pattern, appending a o and then a string of 3 or more characters will locate the string within the pattern. The plugin will attempt to automatically identify if the extended character set should be used however you can force it's use by adding "extended" to the command.    
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --pattern c 1000`     
&nbsp;&nbsp;&nbsp;&nbsp;Example 2: `ERC --pattern o Aa9`   
&nbsp;&nbsp;&nbsp;&nbsp;Example 2: `ERC --pattern o Aa9 extended`   

`--ByteArray`    
The ByteArray option allows the generation of a byte array which is displayed in the log and written to the working directory as both a text file and a binary file containing only the binary values the user wants. By defailt the array will contain all values from 0x00 to 0xFF and values can be omitted by appending them to the command.    
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --bytearray`     
&nbsp;&nbsp;&nbsp;&nbsp;Example 2: `ERC --bytearray 0xFF0x0A \x0b 0C`   

`--Compare`    
Generates a table with a byte by byte comparison of an area of memory and the bytes from a file. Takes a memory address from which to start the search and a filepath for the binary file.
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --Compare 0x12345678 C:\Users\You\Desktop\YourBinaryFile.bin`  

`--Convert`    
Takes a string and converts it to a hex representation. The string can be converted as if it was ASCII, Unicode, UTF-7, UTF-8 or UTF-32. 
&nbsp;&nbsp;&nbsp;&nbsp;Valid conversion types:     
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Ascii to Hex = AtoH    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Unicdoe to Hex = UtoH    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;UTF-7 to Hex = 7toH    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;UTF-8 to Hex = 8toH    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;UTF-32 to Hex = 32toH    
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --Convert AtoH HelloWorld` returns the ASCII bytes for HelloWorld.    
&nbsp;&nbsp;&nbsp;&nbsp;Example 2: `ERC --convert UtoH HelloWorld` returns the Unicode bytes for HelloWorld.

`--Assemble`    
The assemble option can be used to convert assembly instructions into the associated opcodes. The plugin will attempt to identify the architecture required based on the attached process however a 0 can be passed to force 32 bit and a 1 can be passed to force 64 bit. Instructions must be seperated with a comma (,).   
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --Assemble jmp esp`     
&nbsp;&nbsp;&nbsp;&nbsp;Example 2: `ERC --assemble 1 jmp rsp, nop, nop`   

`--Disassemble`    
The disassemble option can be used to convert opcodes into assembly instructions. The plugin will attempt to identify the architecture required based on the attached process however a 0 can be passed to force 32 bit and a 1 can be passed to force 64 bit.    
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --disAssemble FF E4`     
&nbsp;&nbsp;&nbsp;&nbsp;Example 2: `ERC --disassemble 0 FF E4`   

`--SearchMemory`    
Search memory can take a string or set of bytes to search for within the attached process memory and loaded modules. Optionally an integer can be passed to specify the search type (0 = bytes, 1 = Unicode, 2 = ASCII, 4 = UTF7, 5 = UTF8). Modules can be excluded based on certain characteristics (Is ASLR/SafeSEH/Is the binary rebasable/NXCompat(DEP)/Is the binary an OS dll) The values are optional however if you wish to exclude a later value all previous ones must be included.
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --SearchMemory FF E4` Search for bytes FF E4 include all dlls.  
&nbsp;&nbsp;&nbsp;&nbsp;Example 2: `ERC --SearchMemory FF E4 false false false false true` Search for bytes FF E4 excluding only OS dlls.         
&nbsp;&nbsp;&nbsp;&nbsp;Example 3: `ERC --SearchMemory 1 HelloWorld` Search for the ASCII string HelloWorld.

`--Dump`    
Dumps the contents of process memory to the log and a file in the working directory. Takes a hex start address and a hex number for number of bytes to be read.      
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --Dump 0x63428401 0x30`

`--ListProcesses`    
The list processes option takes no parameters and simply lists all visible processes on the machine.    
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --ListProcesses`   

`--ProcessInfo`    
Displays information about the attached process, loaded modules and threads. Can be passed a boolean to indicate if the output should be written to disk.    
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --processInfo`       
&nbsp;&nbsp;&nbsp;&nbsp;Example 2: `ERC --processinfo false` Does not write processinfo output to disk.    

`--ModuleInfo`    
Displays info about the modules loaded by the attached process. Can be passed a boolean to indicate if the output should be written to disk.    
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --moduleInfo`     
&nbsp;&nbsp;&nbsp;&nbsp;Example 2: `ERC --moduleinfo false` Does not write moduleinfo output to disk.   

`--ThreadInfo`    
Displays info about threads associated with the attached process. Can be passed a boolean to indicate if the output should be written to disk.    
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --threadInfo`    
&nbsp;&nbsp;&nbsp;&nbsp;Example 2: `ERC --threadinfo false` Does not write threadinfo output to disk.      

`--SEH`   
Displays a list of addresses for pop pop ret instructions. Can be passed a list of module paths to be ignored in the search.    
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --seh`    
&nbsp;&nbsp;&nbsp;&nbsp;Example 2: `ERC --SEH C:\Path\To\Module\To\Exclude C:\Path\To\Other\Module\To\Exclude`

`--EggHunters`    
Prints a list of egghunters which can be used for various machine types. Can be passed 4 character string to be used as the egghunter search tag. Default tag is ERCD.    
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --egghunters`    
&nbsp;&nbsp;&nbsp;&nbsp;Example 2: `ERC --egghunters ABCD` Egghunters will be generated with the tag "ABCD"    

`--FindNRP`    
Searches process memory for a non repeating pattern specified in the pattern_extended and pattern_standard files. Takes an integer optional to specify the text formating (1 = Unicode, 2 = ASCII, 3 = UTF8, 4 = UTF7, 5 = UTF32, default = ASCII) and can have the parameter "true" passed to indicate the extended pattern should be used.     
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --FindNRP`        
&nbsp;&nbsp;&nbsp;&nbsp;Example 2: `ERC --FindNRP 2 true` Generates FindNRP table after searching for the extended NRP in Unicode format. 

## Author
Andy Bowden 

## Contact 
Andy@evilrobots.club | <img alt="Twitter URL" src="https://img.shields.io/twitter/url?style=social&url=https%3A%2F%2Ftwitter.com%2FAndy53_">
