﻿using System;
using System.Runtime.InteropServices;

namespace SharpAndSimpleHellsGate
{
    public static class Structs
    {

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public UInt16 e_magic;       /*+0x000*/
            public UInt16 e_cblp;        /*+0x002*/
            public UInt16 e_cp;          /*+0x004*/
            public UInt16 e_crlc;        /*+0x006*/
            public UInt16 e_cparhdr;     /*+0x008*/
            public UInt16 e_minalloc;    /*+0x00a*/
            public UInt16 e_maxalloc;    /*+0x00c*/
            public UInt16 e_ss;          /*+0x00e*/
            public UInt16 e_sp;          /*+0x010*/
            public UInt16 e_csum;        /*+0x012*/
            public UInt16 e_ip;          /*+0x014*/
            public UInt16 e_cs;          /*+0x016*/
            public UInt16 e_lfarlc;      /*+0x018*/
            public UInt16 e_ovno;        /*+0x01a*/
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res;       /*+0x01c*/
            public UInt16 e_oemid;       /*+0x024*/
            public UInt16 e_oeminfo;     /*+0x026*/
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;      /*+0x028*/
            public UInt32 e_lfanew;      /*+0x03c*/
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;               /*+0x000*/
            public UInt16 NumberOfSections;      /*+0x002*/
            public UInt32 TimeDateStamp;         /*+0x004*/
            public UInt32 PointerToSymbolTable;  /*+0x008*/
            public UInt32 NumberOfSymbols;       /*+0x00c*/
            public UInt16 SizeOfOptionalHeader;  /*+0x010*/
            public UInt16 Characteristics;       /*+0x012*/
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;  /*+0x000*/
            public UInt32 Size;            /*+0x004*/
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;                             /*+0x000*/
            public Byte MajorLinkerVersion;                  /*+0x002*/
            public Byte MinorLinkerVersion;                  /*+0x003*/
            public UInt32 SizeOfCode;                        /*+0x004*/
            public UInt32 SizeOfInitializedDatal;            /*+0x008*/
            public UInt32 SizeOfUninitializedData;           /*+0x00c*/
            public UInt32 AddressOfEntryPoint;               /*+0x010*/
            public UInt32 BaseOfCode;                        /*+0x014*/
            public UInt64 ImageBasel;                        /*+0x018*/
            public UInt32 SectionAlignment;                  /*+0x020*/
            public UInt32 FileAlignment;                     /*+0x024*/
            public UInt16 MajorOperatingSystemVersion;       /*+0x028*/
            public UInt16 MinorOperatingSystemVersion;       /*+0x02a*/
            public UInt16 MajorImageVersion;                 /*+0x02c*/
            public UInt16 MinorImageVersion;                 /*+0x02e*/
            public UInt16 MajorSubsystemVersion;             /*+0x030*/
            public UInt16 MinorSubsystemVersion;             /*+0x032*/
            public UInt32 Win32VersionValue;                 /*+0x034*/
            public UInt32 SizeOfImage;                       /*+0x038*/
            public UInt32 SizeOfHeaders;                     /*+0x03c*/
            public UInt32 CheckSum;                          /*+0x040*/
            public UInt16 Subsystem;                         /*+0x044*/
            public UInt16 DllCharacteristics;                /*+0x046*/
            public UInt64 SizeOfStackReserve;                /*+0x048*/
            public UInt64 SizeOfStackCommit;                 /*+0x050*/
            public UInt64 SizeOfHeapReserve;                 /*+0x058*/
            public UInt64 SizeOfHeapCommit;                  /*+0x060*/
            public UInt32 LoaderFlags;                       /*+0x068*/
            public UInt32 NumberOfRvaAndSizes;               /*+0x06c*/
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;     /*+0x070*/
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS64
        {
            public UInt32 Signature;                           /*+0x000*/
            public IMAGE_FILE_HEADER FileHeader;               /*+0x004*/
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;     /*+0x018*/
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public UInt32 Characteristics;         /*+0x000*/
            public UInt32 TimeDateStamp;           /*+0x004*/
            public UInt16 MajorVersion;            /*+0x008*/
            public UInt16 MinorVersion;            /*+0x00a*/
            public UInt32 Name;                    /*+0x00c*/
            public UInt32 Base;                    /*+0x010*/
            public UInt32 NumberOfFunctions;       /*+0x014*/
            public UInt32 NumberOfNames;           /*+0x018*/
            public UInt32 AddressOfFunctions;      /*+0x01c*/
            public UInt32 AddressOfNames;          /*+0x020*/
            public UInt32 AddressOfNameOrdinals;   /*+0x024*/
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string Name;                    /*+0x000*/
            public UInt32 Misc;                    /*+0x008*/
            public UInt32 VirtualAddress;          /*+0x00c*/
            public UInt32 SizeOfRawData;           /*+0x010*/
            public UInt32 PointerToRawData;        /*+0x014*/
            public UInt32 PointerToRelocations;    /*+0x018*/
            public UInt32 PointerToLinenumbers;    /*+0x01c*/
            public UInt16 NumberOfRelocations;     /*+0x020*/
            public UInt16 NumberOfLinenumbers;     /*+0x022*/
            public UInt32 Characteristics;         /*+0x024*/
        }

        [StructLayout(LayoutKind.Explicit, Size = 1)]
        public struct LARGE_INTEGER
        {
            [FieldOffset(0)] public Int64 QuadPart;  /*+0x000*/
            [FieldOffset(0)] public UInt32 LowPart;   /*+0x000*/
            [FieldOffset(4)] public UInt32 HighPart;  /*+0x004*/
        }
    }
    public static class Macros
    {

        // NTSTATUS 
        public static bool NT_SUCCESS(UInt32 ntstatus) => ntstatus <= 0x3FFFFFFF;
        public static bool NT_INFORMATION(UInt32 ntstatus) => ntstatus >= 0x40000000 && ntstatus <= 0x7FFFFFFF;
        public static bool NT_WARNING(UInt32 ntstatus) => ntstatus >= 0x80000000 && ntstatus <= 0xBFFFFFFF;
        public static bool NT_ERROR(UInt32 ntstatus) => ntstatus >= 0xC0000000 && ntstatus <= 0xFFFFFFFF;

        // Common NTSTATUS
        public static UInt32 STATUS_SUCCESS { get; } = 0x00000000;
        public static UInt32 STATUS_UNSUCCESSFUL { get; } = 0xC0000001;
        public static UInt32 STATUS_NOT_IMPLEMENTED { get; } = 0xC0000002;

        // Portable Executable
        public static Int16 IMAGE_DOS_SIGNATURE { get; } = 0x5a00 | 0x4D;          // MZ
        public static Int32 IMAGE_NT_SIGNATURE { get; } = 0x00004500 | 0x00000050; // PE00

        // Pseudo-Handles
        public static IntPtr GetCurrentProcess() => new IntPtr(-1);
        public static IntPtr GetCurrentThread() => new IntPtr(-2);
        public static IntPtr GetCurrentProcessToken() => new IntPtr(-4);
        public static IntPtr GetCurrentThreadToken() => new IntPtr(-5);
        public static IntPtr GetCurrentThreadEffectiveToken() => new IntPtr(-6);

        // Page and Memory permissions
        public static UInt32 PAGE_NOACCESS { get; } = 0x01;
        public static UInt32 PAGE_READONLY { get; } = 0x02;
        public static UInt32 PAGE_READWRITE { get; } = 0x04;
        public static UInt32 PAGE_WRITECOPY { get; } = 0x08;
        public static UInt32 PAGE_EXECUTE { get; } = 0x10;
        public static UInt32 PAGE_EXECUTE_READ { get; } = 0x20;
        public static UInt32 PAGE_EXECUTE_READWRITE { get; } = 0x40;
        public static UInt32 PAGE_EXECUTE_WRITECOPY { get; } = 0x80;
        public static UInt32 PAGE_GUARD { get; } = 0x100;
        public static UInt32 PAGE_NOCACHE { get; } = 0x200;
        public static UInt32 PAGE_WRITECOMBINE { get; } = 0x400;
        public static UInt32 PAGE_GRAPHICS_NOACCESS { get; } = 0x0800;
        public static UInt32 PAGE_GRAPHICS_READONLY { get; } = 0x1000;
        public static UInt32 PAGE_GRAPHICS_READWRITE { get; } = 0x2000;
        public static UInt32 PAGE_GRAPHICS_EXECUTE { get; } = 0x4000;
        public static UInt32 PAGE_GRAPHICS_EXECUTE_READ { get; } = 0x8000;
        public static UInt32 PAGE_GRAPHICS_EXECUTE_READWRITE { get; } = 0x10000;
        public static UInt32 PAGE_GRAPHICS_COHERENT { get; } = 0x20000;
        public static UInt32 PAGE_ENCLAVE_THREAD_CONTROL { get; } = 0x80000000;
        public static UInt32 PAGE_REVERT_TO_FILE_MAP { get; } = 0x80000000;
        public static UInt32 PAGE_TARGETS_NO_UPDATE { get; } = 0x40000000;
        public static UInt32 PAGE_TARGETS_INVALID { get; } = 0x40000000;
        public static UInt32 PAGE_ENCLAVE_UNVALIDATED { get; } = 0x20000000;
        public static UInt32 PAGE_ENCLAVE_DECOMMIT { get; } = 0x10000000;
        public static UInt32 MEM_COMMIT { get; } = 0x00001000;
        public static UInt32 MEM_RESERVE { get; } = 0x00002000;
        public static UInt32 MEM_REPLACE_PLACEHOLDER { get; } = 0x00004000;
        public static UInt32 MEM_RESERVE_PLACEHOLDER { get; } = 0x00040000;
        public static UInt32 MEM_RESET { get; } = 0x00080000;
        public static UInt32 MEM_TOP_DOWN { get; } = 0x00100000;
        public static UInt32 MEM_WRITE_WATCH { get; } = 0x00200000;
        public static UInt32 MEM_PHYSICAL { get; } = 0x00400000;
        public static UInt32 MEM_ROTATE { get; } = 0x00800000;
        public static UInt32 MEM_DIFFERENT_IMAGE_BASE_OK { get; } = 0x00800000;
        public static UInt32 MEM_RESET_UNDO { get; } = 0x01000000;
        public static UInt32 MEM_LARGE_PAGES { get; } = 0x20000000;
        public static UInt32 MEM_4MB_PAGES { get; } = 0x80000000;
        public static UInt32 MEM_64K_PAGES { get; } = (MEM_LARGE_PAGES | MEM_PHYSICAL);
        public static UInt32 MEM_UNMAP_WITH_TRANSIENT_BOOST { get; } = 0x00000001;
        public static UInt32 MEM_COALESCE_PLACEHOLDERS { get; } = 0x00000001;
        public static UInt32 MEM_PRESERVE_PLACEHOLDER { get; } = 0x00000002;
        public static UInt32 MEM_DECOMMIT { get; } = 0x00004000;
        public static UInt32 MEM_RELEASE { get; } = 0x00008000;
        public static UInt32 MEM_FREE { get; } = 0x00010000;
    }
}