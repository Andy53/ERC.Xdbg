using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace ERC
{
    namespace Structures
    {
        #region DLL Headers

        #region IMAGE_DOS_HEADER
        /// <summary>
        /// IMAGE_DOS_HEADER.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_DOS_HEADER
        {
            /// <summary>
            /// A pointer to the IMAGE_NT_HEADER.
            /// </summary>
            [FieldOffset(60)] public int nt_head_ptr;
        }
        #endregion

        #region IMAGE_FILE_HEADER
        /// <summary>
        /// IMAGE_FILE_HEADER. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_FILE_HEADER
        {
            /// <summary>
            /// Machine
            /// </summary>
            [FieldOffset(0)] public ushort Machine;
            /// <summary>
            /// NumberOfSections
            /// </summary>
            [FieldOffset(2)] public ushort NumberOfSections;
            /// <summary>
            /// TimeDateStamp
            /// </summary>
            [FieldOffset(4)] public uint TimeDateStamp;
            /// <summary>
            /// PointerToSymbolTable
            /// </summary>
            [FieldOffset(8)] public uint PointerToSymbolTable;
            /// <summary>
            /// NumberOfSymbols
            /// </summary>
            [FieldOffset(12)] public uint NumberOfSymbols;
            /// <summary>
            /// SizeOfOptionalHeader
            /// </summary>
            [FieldOffset(16)] public ushort SizeOfOptionalHeader;
            /// <summary>
            /// Characteristics
            /// </summary>
            [FieldOffset(18)] public ushort Characteristics;
        }
        #endregion

        #region IMAGE_NT_HEADERS
        /// <summary>
        /// IMAGE_NT_HEADER 32 bit variant. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_image_nt_headers
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS32
        {
            /// <summary>
            /// Signature
            /// </summary>
            [FieldOffset(0)] public uint Signature;
            /// <summary>
            /// FileHeader
            /// </summary>
            [FieldOffset(4)] public IMAGE_FILE_HEADER FileHeader;
            /// <summary>
            /// OptionalHeader
            /// </summary>
            [FieldOffset(24)] public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        /// <summary>
        /// IMAGE_NT_HEADER 64 bit variant. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_image_nt_headers
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS64
        {
            /// <summary>
            /// Signature
            /// </summary>
            [FieldOffset(0)] public uint Signature;
            /// <summary>
            /// FileHeader
            /// </summary>
            [FieldOffset(4)] public IMAGE_FILE_HEADER FileHeader;
            /// <summary>
            /// OptionalHeader
            /// </summary>
            [FieldOffset(24)] public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }
        #endregion

        #region IMAGE_DATA_DIRECTORY
        /// <summary>
        /// IMAGE_DATA_DIRECTORY. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_DATA_DIRECTORY
        {
            /// <summary>
            /// VirtualAddress.
            /// </summary>
            [FieldOffset(0)] public uint VirtualAddress;
            /// <summary>
            /// Size.
            /// </summary>
            [FieldOffset(4)] public uint Size;
        }
        #endregion

        #region IMAGE_OPTIONAL_HEADER32
        /// <summary>
        /// IMAGE_OPTIONAL_HEADER 32 bit variant. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_image_optional_header
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            /// <summary>
            /// Magic
            /// </summary>
            [FieldOffset(0)] public MagicType Magic;
            /// <summary>
            /// MajorLinkerVersion
            /// </summary>
            [FieldOffset(2)] public byte MajorLinkerVersion;
            /// <summary>
            /// MinorLinkerVersion
            /// </summary>
            [FieldOffset(3)] public byte MinorLinkerVersion;
            /// <summary>
            /// SizeOfCode
            /// </summary>
            [FieldOffset(4)] public uint SizeOfCode;
            /// <summary>
            /// SizeOfInitializedData
            /// </summary>
            [FieldOffset(8)] public uint SizeOfInitializedData;
            /// <summary>
            /// SizeOfUninitializedData
            /// </summary>
            [FieldOffset(12)] public uint SizeOfUninitializedData;
            /// <summary>
            /// AddressOfEntryPoint
            /// </summary>
            [FieldOffset(16)] public uint AddressOfEntryPoint;
            /// <summary>
            /// BaseOfCode
            /// </summary>
            [FieldOffset(20)] public uint BaseOfCode;
            /// <summary>
            /// BaseOfData
            /// </summary>
            [FieldOffset(24)] public uint BaseOfData;
            /// <summary>
            /// ImageBase
            /// </summary>
            [FieldOffset(28)] public uint ImageBase;
            /// <summary>
            /// SectionAlignment
            /// </summary>
            [FieldOffset(32)] public uint SectionAlignment;
            /// <summary>
            /// FileAlignment
            /// </summary>
            [FieldOffset(36)] public uint FileAlignment;
            /// <summary>
            /// MajorOperatingSystemVersion
            /// </summary>
            [FieldOffset(40)] public ushort MajorOperatingSystemVersion;
            /// <summary>
            /// MinorOperatingSystemVersion
            /// </summary>
            [FieldOffset(42)] public ushort MinorOperatingSystemVersion;
            /// <summary>
            /// MajorImageVersion
            /// </summary>
            [FieldOffset(44)] public ushort MajorImageVersion;
            /// <summary>
            /// MinorImageVersion
            /// </summary>
            [FieldOffset(46)] public ushort MinorImageVersion;
            /// <summary>
            /// MajorSubsystemVersion
            /// </summary>
            [FieldOffset(48)] public ushort MajorSubsystemVersion;
            /// <summary>
            /// MinorSubsystemVersion
            /// </summary>
            [FieldOffset(50)] public ushort MinorSubsystemVersion;
            /// <summary>
            /// Win32VersionValue
            /// </summary>
            [FieldOffset(52)] public uint Win32VersionValue;
            /// <summary>
            /// SizeOfImage
            /// </summary>
            [FieldOffset(56)] public uint SizeOfImage;
            /// <summary>
            /// SizeOfHeaders
            /// </summary>
            [FieldOffset(60)] public uint SizeOfHeaders;
            /// <summary>
            /// CheckSum
            /// </summary>
            [FieldOffset(64)] public uint CheckSum;
            /// <summary>
            /// Subsystem
            /// </summary>
            [FieldOffset(68)] public SubSystemType Subsystem;
            /// <summary>
            /// DllCharacteristics
            /// </summary>
            [FieldOffset(70)] public ushort DllCharacteristics;
            /// <summary>
            /// SizeOfStackReserve
            /// </summary>
            [FieldOffset(72)] public uint SizeOfStackReserve;
            /// <summary>
            /// SizeOfStackCommit
            /// </summary>
            [FieldOffset(76)] public uint SizeOfStackCommit;
            /// <summary>
            /// SizeOfHeapReserve
            /// </summary>
            [FieldOffset(80)] public uint SizeOfHeapReserve;
            /// <summary>
            /// SizeOfHeapCommit
            /// </summary>
            [FieldOffset(84)] public uint SizeOfHeapCommit;
            /// <summary>
            /// LoaderFlags
            /// </summary>
            [FieldOffset(88)] public uint LoaderFlags;
            /// <summary>
            /// NumberOfRvaAndSizes
            /// </summary>
            [FieldOffset(92)] public uint NumberOfRvaAndSizes;
            /// <summary>
            /// ExportTable
            /// </summary>
            [FieldOffset(96)] public IMAGE_DATA_DIRECTORY ExportTable;
            /// <summary>
            /// ImportTable
            /// </summary>
            [FieldOffset(104)] public IMAGE_DATA_DIRECTORY ImportTable;
            /// <summary>
            /// ResourceTable
            /// </summary>
            [FieldOffset(112)] public IMAGE_DATA_DIRECTORY ResourceTable;
            /// <summary>
            /// ExceptionTable
            /// </summary>
            [FieldOffset(120)] public IMAGE_DATA_DIRECTORY ExceptionTable;
            /// <summary>
            /// CertificateTable
            /// </summary>
            [FieldOffset(128)] public IMAGE_DATA_DIRECTORY CertificateTable;
            /// <summary>
            /// BaseRelocationTable
            /// </summary>
            [FieldOffset(136)] public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            /// <summary>
            /// Debug
            /// </summary>
            [FieldOffset(144)] public IMAGE_DATA_DIRECTORY Debug;
            /// <summary>
            /// Architecture
            /// </summary>
            [FieldOffset(152)] public IMAGE_DATA_DIRECTORY Architecture;
            /// <summary>
            /// GlobalPtr
            /// </summary>
            [FieldOffset(160)] public IMAGE_DATA_DIRECTORY GlobalPtr;
            /// <summary>
            /// TLSTable
            /// </summary>
            [FieldOffset(168)] public IMAGE_DATA_DIRECTORY TLSTable;
            /// <summary>
            /// LoadConfigTable
            /// </summary>
            [FieldOffset(176)] public IMAGE_DATA_DIRECTORY LoadConfigTable;
            /// <summary>
            /// BoundImport
            /// </summary>
            [FieldOffset(184)] public IMAGE_DATA_DIRECTORY BoundImport;
            /// <summary>
            /// IAT
            /// </summary>
            [FieldOffset(192)] public IMAGE_DATA_DIRECTORY IAT;
            /// <summary>
            /// DelayImportDescriptor
            /// </summary>
            [FieldOffset(200)] public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            /// <summary>
            /// CLRRuntimeHeader
            /// </summary>
            [FieldOffset(208)] public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            /// <summary>
            /// Reserved
            /// </summary>
            [FieldOffset(216)] public IMAGE_DATA_DIRECTORY Reserved;
        }
        #endregion

        #region IMAGE_OPTIONAL_HEADER64
        /// <summary>
        /// IMAGE_OPTIONAL_HEADER 64 bit variant. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_image_optional_header
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            /// <summary>
            /// Magic
            /// </summary>
            [FieldOffset(0)] public MagicType Magic;
            /// <summary>
            /// MajorLinkerVersion
            /// </summary>
            [FieldOffset(2)] public byte MajorLinkerVersion;
            /// <summary>
            /// MinorLinkerVersion
            /// </summary>
            [FieldOffset(3)] public byte MinorLinkerVersion;
            /// <summary>
            /// SizeOfCode
            /// </summary>
            [FieldOffset(4)] public uint SizeOfCode;
            /// <summary>
            /// SizeOfInitializedData
            /// </summary>
            [FieldOffset(8)] public uint SizeOfInitializedData;
            /// <summary>
            /// SizeOfUninitializedData
            /// </summary>
            [FieldOffset(12)] public uint SizeOfUninitializedData;
            /// <summary>
            /// AddressOfEntryPoint
            /// </summary>
            [FieldOffset(16)] public uint AddressOfEntryPoint;
            /// <summary>
            /// BaseOfCode
            /// </summary>
            [FieldOffset(20)] public uint BaseOfCode;
            /// <summary>
            /// ImageBase
            /// </summary>
            [FieldOffset(24)] public ulong ImageBase;
            /// <summary>
            /// SectionAlignment
            /// </summary>
            [FieldOffset(32)] public uint SectionAlignment;
            /// <summary>
            /// FileAlignment
            /// </summary>
            [FieldOffset(36)] public uint FileAlignment;
            /// <summary>
            /// MajorOperatingSystemVersion
            /// </summary>
            [FieldOffset(40)] public ushort MajorOperatingSystemVersion;
            /// <summary>
            /// MinorOperatingSystemVersion
            /// </summary>
            [FieldOffset(42)] public ushort MinorOperatingSystemVersion;
            /// <summary>
            /// MajorImageVersion
            /// </summary>
            [FieldOffset(44)] public ushort MajorImageVersion;
            /// <summary>
            /// MinorImageVersion
            /// </summary>
            [FieldOffset(46)] public ushort MinorImageVersion;
            /// <summary>
            /// MajorSubsystemVersion
            /// </summary>
            [FieldOffset(48)] public ushort MajorSubsystemVersion;
            /// <summary>
            /// MinorSubsystemVersion
            /// </summary>
            [FieldOffset(50)] public ushort MinorSubsystemVersion;
            /// <summary>
            /// Win32VersionValue
            /// </summary>
            [FieldOffset(52)] public uint Win32VersionValue;
            /// <summary>
            /// SizeOfImage
            /// </summary>
            [FieldOffset(56)] public uint SizeOfImage;
            /// <summary>
            /// SizeOfHeaders
            /// </summary>
            [FieldOffset(60)] public uint SizeOfHeaders;
            /// <summary>
            /// CheckSum
            /// </summary>
            [FieldOffset(64)] public uint CheckSum;
            /// <summary>
            /// Subsystem
            /// </summary>
            [FieldOffset(68)] public SubSystemType Subsystem;
            /// <summary>
            /// DllCharacteristics
            /// </summary>
            [FieldOffset(70)] public ushort DllCharacteristics;
            /// <summary>
            /// SizeOfStackReserve
            /// </summary>
            [FieldOffset(72)] public ulong SizeOfStackReserve;
            /// <summary>
            /// SizeOfStackCommit
            /// </summary>
            [FieldOffset(80)] public ulong SizeOfStackCommit;
            /// <summary>
            /// SizeOfHeapReserve
            /// </summary>
            [FieldOffset(88)] public ulong SizeOfHeapReserve;
            /// <summary>
            /// SizeOfHeapCommit
            /// </summary>
            [FieldOffset(96)] public ulong SizeOfHeapCommit;
            /// <summary>
            /// LoaderFlags
            /// </summary>
            [FieldOffset(104)] public uint LoaderFlags;
            /// <summary>
            /// NumberOfRvaAndSizes
            /// </summary>
            [FieldOffset(108)] public uint NumberOfRvaAndSizes;
            /// <summary>
            /// ExportTable
            /// </summary>
            [FieldOffset(112)] public IMAGE_DATA_DIRECTORY ExportTable;
            /// <summary>
            /// ImportTable
            /// </summary>
            [FieldOffset(120)] public IMAGE_DATA_DIRECTORY ImportTable;
            /// <summary>
            /// ResourceTable
            /// </summary>
            [FieldOffset(128)] public IMAGE_DATA_DIRECTORY ResourceTable;
            /// <summary>
            /// ExceptionTable
            /// </summary>
            [FieldOffset(136)] public IMAGE_DATA_DIRECTORY ExceptionTable;
            /// <summary>
            /// CertificateTable
            /// </summary>
            [FieldOffset(144)] public IMAGE_DATA_DIRECTORY CertificateTable;
            /// <summary>
            /// BaseRelocationTable
            /// </summary>
            [FieldOffset(152)] public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            /// <summary>
            /// Debug
            /// </summary>
            [FieldOffset(160)] public IMAGE_DATA_DIRECTORY Debug;
            /// <summary>
            /// Architecture
            /// </summary>
            [FieldOffset(168)] public IMAGE_DATA_DIRECTORY Architecture;
            /// <summary>
            /// GlobalPtr
            /// </summary>
            [FieldOffset(176)] public IMAGE_DATA_DIRECTORY GlobalPtr;
            /// <summary>
            /// TLSTable
            /// </summary>
            [FieldOffset(184)] public IMAGE_DATA_DIRECTORY TLSTable;
            /// <summary>
            /// LoadConfigTable
            /// </summary>
            [FieldOffset(192)] public IMAGE_DATA_DIRECTORY LoadConfigTable;
            /// <summary>
            /// BoundImport
            /// </summary>
            [FieldOffset(200)] public IMAGE_DATA_DIRECTORY BoundImport;
            /// <summary>
            /// IAT
            /// </summary>
            [FieldOffset(208)] public IMAGE_DATA_DIRECTORY IAT;
            /// <summary>
            /// DelayImportDescriptor
            /// </summary>
            [FieldOffset(216)] public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            /// <summary>
            /// CLRRuntimeHeader
            /// </summary>
            [FieldOffset(224)] public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            /// <summary>
            /// Reserved
            /// </summary>
            [FieldOffset(232)] public IMAGE_DATA_DIRECTORY Reserved;
        }
        #endregion

        #region MagicType
        /// <summary>
        /// Image Option Header Magic Type.
        /// </summary>
        public enum MagicType : ushort
        {
            /// <summary>
            /// IMAGE_NT_OPTIONAL_HDR32_MAGIC
            /// </summary>
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            /// <summary>
            /// IMAGE_NT_OPTIONAL_HDR64_MAGIC
            /// </summary>
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }
        #endregion

        #region SubSystemType
        /// <summary>
        /// Image Option Header SubSystem Type.
        /// </summary>
        public enum SubSystemType : ushort
        {
            /// <summary>
            /// IMAGE_SUBSYSTEM_UNKNOWN
            /// </summary>
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            /// <summary>
            /// IMAGE_SUBSYSTEM_NATIVE
            /// </summary>
            IMAGE_SUBSYSTEM_NATIVE = 1,
            /// <summary>
            /// IMAGE_SUBSYSTEM_WINDOWS_GUI
            /// </summary>
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            /// <summary>
            /// IMAGE_SUBSYSTEM_WINDOWS_CUI
            /// </summary>
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            /// <summary>
            /// IMAGE_SUBSYSTEM_POSIX_CUI
            /// </summary>
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            /// <summary>
            /// IMAGE_SUBSYSTEM_WINDOWS_CE_GUI
            /// </summary>
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            /// <summary>
            /// IMAGE_SUBSYSTEM_EFI_APPLICATION
            /// </summary>
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            /// <summary>
            /// IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER
            /// </summary>
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            /// <summary>
            /// IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER
            /// </summary>
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            /// <summary>
            /// IMAGE_SUBSYSTEM_EFI_ROM
            /// </summary>
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            /// <summary>
            /// IMAGE_SUBSYSTEM_XBOX
            /// </summary>
            IMAGE_SUBSYSTEM_XBOX = 14
        }
        #endregion

        #region IMAGE_LOAD_CONFIG_DIRECTORY32
        /// <summary>
        /// IMAGE_LOAD_CONFIG_DIRECTORY32. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_image_load_config_directory32
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_LOAD_CONFIG_DIRECTORY32
        {
            /// <summary>
            /// Size
            /// </summary>
            public uint Size;
            /// <summary>
            /// TimeDateStamp
            /// </summary>
            public uint TimeDateStamp;
            /// <summary>
            /// MajorVersio
            /// </summary>
            public ushort MajorVersion;
            /// <summary>
            /// MinorVersion
            /// </summary>
            public ushort MinorVersion;
            /// <summary>
            /// GlobalFlagsClear
            /// </summary>
            public uint GlobalFlagsClear;
            /// <summary>
            /// GlobalFlagsSet
            /// </summary>
            public uint GlobalFlagsSet;
            /// <summary>
            /// CriticalSectionDefaultTimeout
            /// </summary>
            public uint CriticalSectionDefaultTimeout;
            /// <summary>
            /// DeCommitFreeBlockThreshold
            /// </summary>
            public uint DeCommitFreeBlockThreshold;
            /// <summary>
            /// DeCommitTotalFreeThreshold
            /// </summary>
            public uint DeCommitTotalFreeThreshold;
            /// <summary>
            /// LockPrefixTable
            /// </summary>
            public uint LockPrefixTable;
            /// <summary>
            /// MaximumAllocationSize
            /// </summary>
            public uint MaximumAllocationSize;
            /// <summary>
            /// VirtualMemoryThreshold
            /// </summary>
            public uint VirtualMemoryThreshold;
            /// <summary>
            /// ProcessHeapFlags
            /// </summary>
            public uint ProcessHeapFlags;
            /// <summary>
            /// ProcessAffinityMask
            /// </summary>
            public uint ProcessAffinityMask;
            /// <summary>
            /// CSDVersion
            /// </summary>
            public ushort CSDVersion;
            /// <summary>
            /// DependentLoadFlags
            /// </summary>
            public ushort DependentLoadFlags;
            /// <summary>
            /// EditList
            /// </summary>
            public uint EditList;
            /// <summary>
            /// SecurityCookie
            /// </summary>
            public uint SecurityCookie;
            /// <summary>
            /// SEHandlerTable
            /// </summary>
            public uint SEHandlerTable;
            /// <summary>
            /// SEHandlerCount
            /// </summary>
            public uint SEHandlerCount;
            /// <summary>
            /// GuardCFCheckFunctionPointer
            /// </summary>
            public uint GuardCFCheckFunctionPointer;
            /// <summary>
            /// GuardCFDispatchFunctionPointer
            /// </summary>
            public uint GuardCFDispatchFunctionPointer;
            /// <summary>
            /// GuardCFFunctionTable
            /// </summary>
            public uint GuardCFFunctionTable;
            /// <summary>
            /// GuardCFFunctionCount
            /// </summary>
            public uint GuardCFFunctionCount;
            /// <summary>
            /// GuardFlags
            /// </summary>
            public uint GuardFlags;
            /// <summary>
            /// CodeIntegrity
            /// </summary>
            public IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
            /// <summary>
            /// GuardAddressTakenIatEntryTable
            /// </summary>
            public uint GuardAddressTakenIatEntryTable;
            /// <summary>
            /// GuardAddressTakenIatEntryCount
            /// </summary>
            public uint GuardAddressTakenIatEntryCount;
            /// <summary>
            /// GuardLongJumpTargetTable
            /// </summary>
            public uint GuardLongJumpTargetTable;
            /// <summary>
            /// GuardLongJumpTargetCount
            /// </summary>
            public uint GuardLongJumpTargetCount;
            /// <summary>
            /// DynamicValueRelocTable
            /// </summary>
            public uint DynamicValueRelocTable;
            /// <summary>
            /// CHPEMetadataPointer
            /// </summary>
            public uint CHPEMetadataPointer;
            /// <summary>
            /// GuardRFFailureRoutine
            /// </summary>
            public uint GuardRFFailureRoutine;
            /// <summary>
            /// GuardRFFailureRoutineFunctionPointer
            /// </summary>
            public uint GuardRFFailureRoutineFunctionPointer;
            /// <summary>
            /// DynamicValueRelocTableOffset
            /// </summary>
            public uint DynamicValueRelocTableOffset;
            /// <summary>
            /// DynamicValueRelocTableSection
            /// </summary>
            public ushort DynamicValueRelocTableSection;
            /// <summary>
            /// Reserved2
            /// </summary>
            public ushort Reserved2;
            /// <summary>
            /// GuardRFVerifyStackPointerFunctionPointer
            /// </summary>
            public uint GuardRFVerifyStackPointerFunctionPointer;
            /// <summary>
            /// HotPatchTableOffset
            /// </summary>
            public uint HotPatchTableOffset;
            /// <summary>
            /// Reserved3
            /// </summary>
            public uint Reserved3;
            /// <summary>
            /// EnclaveConfigurationPointer
            /// </summary>
            public uint EnclaveConfigurationPointer;
            /// <summary>
            /// VolatileMetadataPointer
            /// </summary>
            public uint VolatileMetadataPointer;
        }
        #endregion

        #region IMAGE_LOAD_CONFIG_DIRECTORY64
        /// <summary>
        /// IMAGE_LOAD_CONFIG_DIRECTORY32. See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_image_load_config_directory64
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_LOAD_CONFIG_DIRECTORY64
        {
            /// <summary>
            /// Size
            /// </summary>
            public uint Size;
            /// <summary>
            /// TimeDateStamp
            /// </summary>
            public uint TimeDateStamp;
            /// <summary>
            /// MajorVersion
            /// </summary>
            public ushort MajorVersion;
            /// <summary>
            /// MinorVersion
            /// </summary>
            public ushort MinorVersion;
            /// <summary>
            /// GlobalFlagsClear
            /// </summary>
            public uint GlobalFlagsClear;
            /// <summary>
            /// GlobalFlagsSet
            /// </summary>
            public uint GlobalFlagsSet;
            /// <summary>
            /// CriticalSectionDefaultTimeout
            /// </summary>
            public uint CriticalSectionDefaultTimeout;
            /// <summary>
            /// DeCommitFreeBlockThreshold
            /// </summary>
            public ulong DeCommitFreeBlockThreshold;
            /// <summary>
            /// DeCommitTotalFreeThreshold
            /// </summary>
            public ulong DeCommitTotalFreeThreshold;
            /// <summary>
            /// LockPrefixTable
            /// </summary>
            public ulong LockPrefixTable;
            /// <summary>
            /// MaximumAllocationSize
            /// </summary>
            public ulong MaximumAllocationSize;
            /// <summary>
            /// VirtualMemoryThreshold
            /// </summary>
            public ulong VirtualMemoryThreshold;
            /// <summary>
            /// ProcessAffinityMask
            /// </summary>
            public ulong ProcessAffinityMask;
            /// <summary>
            /// ProcessHeapFlags
            /// </summary>
            public uint ProcessHeapFlags;
            /// <summary>
            /// CSDVersion
            /// </summary>
            public ushort CSDVersion;
            /// <summary>
            /// DependentLoadFlags
            /// </summary>
            public ushort DependentLoadFlags;
            /// <summary>
            /// EditList
            /// </summary>
            public ulong EditList;
            /// <summary>
            /// SecurityCookie
            /// </summary>
            public ulong SecurityCookie;
            /// <summary>
            /// SEHandlerTable
            /// </summary>
            public ulong SEHandlerTable;
            /// <summary>
            /// SEHandlerCount
            /// </summary>
            public ulong SEHandlerCount;
            /// <summary>
            /// GuardCFCheckFunctionPointer
            /// </summary>
            public ulong GuardCFCheckFunctionPointer;
            /// <summary>
            /// GuardCFDispatchFunctionPointer
            /// </summary>
            public ulong GuardCFDispatchFunctionPointer;
            /// <summary>
            /// GuardCFFunctionTable
            /// </summary>
            public ulong GuardCFFunctionTable;
            /// <summary>
            /// GuardCFFunctionCount
            /// </summary>
            public ulong GuardCFFunctionCount;
            /// <summary>
            /// GuardFlags
            /// </summary>
            public uint GuardFlags;
            /// <summary>
            /// CodeIntegrity
            /// </summary>
            public IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
            /// <summary>
            /// GuardAddressTakenIatEntryTable
            /// </summary>
            public ulong GuardAddressTakenIatEntryTable;
            /// <summary>
            /// GuardAddressTakenIatEntryCount
            /// </summary>
            public ulong GuardAddressTakenIatEntryCount;
            /// <summary>
            /// GuardLongJumpTargetTable
            /// </summary>
            public ulong GuardLongJumpTargetTable;
            /// <summary>
            /// GuardLongJumpTargetCount
            /// </summary>
            public ulong GuardLongJumpTargetCount;
            /// <summary>
            /// DynamicValueRelocTable
            /// </summary>
            public ulong DynamicValueRelocTable;
            /// <summary>
            /// CHPEMetadataPointer
            /// </summary>
            public ulong CHPEMetadataPointer;
            /// <summary>
            /// GuardRFFailureRoutine
            /// </summary>
            public ulong GuardRFFailureRoutine;
            /// <summary>
            /// GuardRFFailureRoutineFunctionPointer
            /// </summary>
            public ulong GuardRFFailureRoutineFunctionPointer;
            /// <summary>
            /// DynamicValueRelocTableOffset
            /// </summary>
            public uint DynamicValueRelocTableOffset;
            /// <summary>
            /// DynamicValueRelocTableSection
            /// </summary>
            public ushort DynamicValueRelocTableSection;
            /// <summary>
            /// Reserved2
            /// </summary>
            public ushort Reserved2;
            /// <summary>
            /// GuardRFVerifyStackPointerFunctionPointer
            /// </summary>
            public ulong GuardRFVerifyStackPointerFunctionPointer;
            /// <summary>
            /// HotPatchTableOffset
            /// </summary>
            public uint HotPatchTableOffset;
            /// <summary>
            /// Reserved3
            /// </summary>
            public uint Reserved3;
            /// <summary>
            /// EnclaveConfigurationPointer
            /// </summary>
            public ulong EnclaveConfigurationPointer;
            /// <summary>
            /// VolatileMetadataPointer
            /// </summary>
            public ulong VolatileMetadataPointer;
        }
        #endregion

        #region IMAGE_LOAD_CONFIG_CODE_INTEGRITY
        /// <summary>
        /// IMAGE_LOAD_CONFIG_CODE_INTEGRITY.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY
        {
            /// <summary>
            /// Flags
            /// </summary>
            public ushort Flags;
            /// <summary>
            /// Catalog
            /// </summary>
            public ushort Catalog;
            /// <summary>
            /// CatalogOffset
            /// </summary>
            public uint CatalogOffset;
            /// <summary>
            /// Reserved
            /// </summary>
            public uint Reserved;
        };
        #endregion

        #region LOADED_IMAGE
        /// <summary>
        /// LOADED_IMAGE. See https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-_loaded_image
        /// </summary>
        public struct LOADED_IMAGE
        {
            /// <summary>
            /// ModuleName
            /// </summary>
            public IntPtr ModuleName;
            /// <summary>
            /// hFile
            /// </summary>
            public IntPtr hFile;
            /// <summary>
            /// MappedAddress
            /// </summary>
            public IntPtr MappedAddress;
            /// <summary>
            /// FileHeader
            /// </summary>
            public IntPtr FileHeader;
            /// <summary>
            /// LastRvaSection
            /// </summary>
            public IntPtr LastRvaSection;
            /// <summary>
            /// NumberOfSections
            /// </summary>
            public uint NumberOfSections;
            /// <summary>
            /// Sections
            /// </summary>
            public IntPtr Sections;
            /// <summary>
            /// Characteristics
            /// </summary>
            public uint Characteristics;
            /// <summary>
            /// fSystemImage
            /// </summary>
            public bool fSystemImage;
            /// <summary>
            /// fDOSImage
            /// </summary>
            public bool fDOSImage;
            /// <summary>
            /// fReadOnly
            /// </summary>
            public bool fReadOnly;
            /// <summary>
            /// Version
            /// </summary>
            public byte Version;
            /// <summary>
            /// Links
            /// </summary>
            public LIST_ENTRY Links;
            /// <summary>
            /// SizeOfImage
            /// </summary>
            public uint SizeOfImage;
        }
        #endregion

        #region List_Entry
        /// <summary>
        /// Describes an entry in a doubly linked list or serves as the header for such a list. See https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_list_entry
        /// </summary>
        public struct LIST_ENTRY
        {
            /// <summary>
            /// Flink points to the next entry in the list.
            /// </summary>
            public IntPtr Flink;
            /// <summary>
            /// Blink points to the previous entry in the list.
            /// </summary>
            public IntPtr Blink;
        }
        #endregion

        #endregion

    }
}
