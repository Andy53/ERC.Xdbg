# ERC.Xdbg
An X64dbg Plugin of the [ERC](https://github.com/Andy53/ERC.net) Library.

## Installation
Installing the plugin is reasonably straight forward. Simply download the appropriate zip package for your architecture from the releases page of this repoistory and save then unzip it in the plugins directory of X64dbg. If X64dbg does not currently have a plugins directory then run it once to create the intial directory structure.

If you wish to build the plugin from source simply clone the Git repository, open the solution in Visual Studio and build the project targeted for your architecture of choice. Then copy the binaries into the plugins directory of your X64dbg installation.

# Usage
Instructions on usage of the plugin can be seen below. This can also be accessed directly through the debugger using `ERC --help`. 

Details on each command can be seen below. Commands are not case sensitive.

`--Help`       
Displays the help message below.    
&nbsp;&nbsp;&nbsp;&nbsp;Example: `ERC --help`    

`--Update`
Downloads the latest release of the plugin from Github and extracts it into the X64Dbg plugin directory for the architecture currently in use. Can be passed a ip:port pair in order to specify a proxy.
&nbsp;&nbsp;&nbsp;&nbsp;Example 1: `ERC --update 127.0.0.1:8080`

`--config`    
The config option can be used to set values in the config.xml file. Can be used to set things such as the project author, current working directory and error log file. These options are predominatly used when writing the output of operations to file.    
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


```
    __________   ______  
   / ____ / __\ / ____/ 
  / __ / / /_/ / /       
 / /___ / _, _/ /___     
/_____ /_/ |_|\____/    
-------------------------
Error: Arguments must be provided. Use --help for detailed information.
Usage:       
   --Help          |
       Displays this message. Further help can be found at: https://github.com/Andy53/ERC.Xdbg/tree/master/ErcXdbg 
   --Config        |
       Takes any of the following arguments, Get requests take no additional parameters, Set requests take a directory
       which will be set as the new value.
           GetWorkingDirectory (ERC --config GetWorkingDirectory)
           GetStandardPattern  (ERC --config GetStandardPatter)
           GetExtendedPattern  (ERC --config GetExtendedPattern)
           GetVersion          (ERC --config GetVersion)
           GetAuthor           (ERC --config GetAuthor)
           GetErrorFilePath    (ERC --config GetErrorFilePath)
           SetWorkingDirectory (ERC --config SetWorkingDirectory directory)
           SetStandardPattern  (ERC --config SetStandardPattern file)
           SetExtendedPattern  (ERC --config SetExtendedPattern file)
           SetAuthor           (ERC --config SetAuthor author)
           SetErrorFilePath    (ERC --config SetErrorFilePath file)
   --Pattern       |
       Generates a non repeating pattern. A pattern of pure ASCII characters can be generated up to 20277 and up to  
       66923 if special characters are used. The offset of a particular string can be found inside the pattern by 
       providing a search string (must be at least 3 chars long).
           Pattern create: ERC --pattern <create | c> <length>
           Pattern offset: ERC --pattern <offset | o> <search string>
   --Bytearray     |
       Generates a bytearray which is saved to the working directory and displayed in the application log tab. A set 
       of hex characters can be provided which will be excluded from the bytearray.
   --Compare       |
       Generates a table with a byte by byte comparison of an area of memory and the bytes from a file. Takes a memory 
       from which to start the search and a filepath for the binary file
   --Convert       |
       Converts input from one form to another such as ASCII to hex, Unicode to hex, ASCII to bytes. 
       Valid conversion types:
           Ascii to Hex = AtoH
           Unicdoe to Hex = UtoH
           UTF-7 to Hex = 7toH
           UTF-8 to Hex = 8toH
           UTF-32 to Hex = 32toH
   --Assemble      |
       Takes a collection of assembley instructions and outputs the associated opcodes. Takes a boolean of 0 for x32 or
        1 for x64 can be used to force the architecture of the opcodes returned, if neither is passed the architecture 
       of the process will be used.
   --Disassemble   |
       Takes a collection of opcodes and outputs the associated assembley instructions. Takes a boolean of 0 for x32 or
        1 for x64 can be used to force the architecture of the opcodes returned, if neither is passed the architecture 
       of the process will be used.
   --SearchMemory   |
       Takes a search string of either bytes or a string to search for. Takes an (optional) integer to specify search 
       type (0 = bytes, 1 = Unicode, 2 = ASCII, 4 = UTF7, 5 = UTF8). Additionally boolean values of true or false can 
       be used to exclude modules from the search with certain characteristics. The values are optional however if 
       you wish to exclude a later value all previous ones must be included. Order is ASLR, SAFESEH, REBASE, NXCOMPAT, 
       OSDLL.
       Example: ERC --SearchMemory FF E4 false false false false true. Search for bytes FF E4 excluding only OS dll's
       Example: ERC --SearchMemory FF E4. Search for bytes FF E4 including all dll's 
       Example: ERC --SearchMemory FF E4 true true. Search for bytes FF E4 excluding only dll's with ASLR and SafeSEH
       enabled
   --ListProcesses |
       Displays a list of processes running on the local machine.
   --ProcessInfo   |
       Displays info about the attached process, loaded modules and threads. Can be passed a boolen to indicate if the
       output should be written to disk.
   --ModuleInfo    |
       Displays info about the modules loaded by the attached process. Can be passed a boolen to indicate if the output
       should be written to disk.
   --ThreadInfo    |
       Displays info about threads associated with the attached process. Can be passed a boolen to indicate if the
       output should be written to disk.
   --SEH           |
       Displays a list of addresses for pop pop ret instructions. Can be passed a list of module paths to be ignored
       in the search.
   --EggHunters    |
       Prints a list of egghunters which can be used for various machine types. Can be passed 4 character string to be
       used as the egghunter search tag. Default tag is ERCD.
   --FindNrp       |
       Generates a table detailing whether a repeating pattern has been found in the memory space of the process and
       if any registers pointed into the pattern. Takes an integer for the text to look for (1 = Unicode, 2 = ASCII,
       3 = UTF8, 4 = UTF7, 5 = UTF32, default = ASCII). Additionally if the value "True" is provided the extended 
       pattern will be used which includes special characters.
   ```
