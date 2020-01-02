# ERC.Xdbg
An X64dbg Plugin of the [ERC](https://github.com/Andy53/ERC.net) Library.

## Installation
Installing the plugin is reasonably straight forward. Simply download the appropriate zip package for your architecture from the releases page of this repoistory and save then unzip it in the plugins directory of X64dbg. If X64dbg does not currently have a plugins directory then run it once to create the intial directory structure.

# Usage
Instructions on usage of the plugin can be seen below. This can also be accessed directly through the debugger using `ERC --help`. More detailed usage information for each option can be found below (to be completed)

```    __________   ______  
   / ____ / __\ / ____/ 
  / __ / / /_/ / /       
 / /___ / _, _/ /___     
/_____ /_/ |_|\____/    
-------------------------
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
       Generates a bytearray which is saved to the working directory and displayed in the application log tab. An set 
       hex characters can be provided which will be excluded from the bytearray.   --Compare       |
       Generates a table with a byte by byte comparison of an area of memory and the bytes from a file. Takes a memory 
       from which to start the search and a filepath for the binary file
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
       type (0 = bytes, 1 = Unicode, 2 = ASCII, 4 = UTF7, 5 = UTF8. Additionally boolean values of true or false can 
       be used to exclude modules from the search with certain characteristics. The values are optional however if 
       you wish to exclude a later value all previous ones must be included. Order is ASLR, SAFESEH, REBASE, NXCOMPAT, 
       OSDLL.
       Example: ERC --SearchMemory FF E4 false false false false true. Search for bytes FF E4 excluding only OS dlls
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
   --Rop           |
       Much like the lottery you can try your luck and your life may get much easier, however it probably wont...```
