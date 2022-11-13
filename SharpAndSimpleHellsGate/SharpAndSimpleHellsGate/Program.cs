using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Reflection;
namespace SharpAndSimpleHellsGate
{
    class Program
    {
        public static uint Gate() { return 5;  }
        static void Main(string[] args)
        {
            IntPtr freeRWX = initializeRWX();
            SystemModule ntdll = new SystemModule("ntdll.dll");
            ntdll.LoadAllStructures();

            IntPtr baseAddr = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)3000;
            object[] allocArgs = new object[] { (IntPtr)(-1), baseAddr, IntPtr.Zero, regionSize, Macros.MEM_COMMIT , Macros.PAGE_EXECUTE_READWRITE};
            Console.WriteLine($"Allocate Id is {ntdll.GetSyscallId("NtAllocateVirtualMemory")}");
            Console.WriteLine("Ntstatus for Allocate: 0x{0:X}", (uint)directSyscall<Delegates.NtAllocateVirtualMemory>(ntdll.GetSyscallId("NtAllocateVirtualMemory"), freeRWX, allocArgs));
            Console.WriteLine("Allocated to 0x{0:X}", (long)(IntPtr)allocArgs[1]);
            baseAddr = (IntPtr)allocArgs[1];
            regionSize = (IntPtr)allocArgs[3];

            Console.WriteLine($"Protect Id is {ntdll.GetSyscallId("NtProtectVirtualMemory")}");
            Console.WriteLine("Ntstatus for Protect: 0x{0:X}", (uint)directSyscall<Delegates.NtProtectVirtualMemory>(ntdll.GetSyscallId("NtProtectVirtualMemory"), freeRWX, new object[] { (IntPtr)(-1), baseAddr, regionSize, Macros.PAGE_EXECUTE_READ, (uint)0}));
        }
        public static IntPtr initializeRWX()
        {
            MethodInfo method = typeof(Program).GetMethod(nameof(Gate), BindingFlags.Static | BindingFlags.Public);
            RuntimeHelpers.PrepareMethod(method.MethodHandle);

            IntPtr pMethod = method.MethodHandle.GetFunctionPointer();
            if (Marshal.ReadByte(pMethod) != 0xe9)
            {
                Console.WriteLine("Invalid Stub, the method table probably has the machine code instead of a JMP");
                return pMethod;
            }
            Int32 offset = Marshal.ReadInt32(pMethod, 1);
            UInt64 addr = (UInt64)pMethod + (UInt64)offset;
            while (addr % 16 != 0) addr++;
            return (IntPtr)addr;
        }
        public static object directSyscall<T>(short callId, IntPtr RWX, object[] args) where T : Delegate
        { 
            byte[] stub = new byte[] {
                0x4c, 0x8b, 0xd1,                                      // mov  r10, rcx
                0xb8, (byte)callId, (byte)(callId >> 8), 0x00, 0x00,   // mov  eax, <syscall
                0x0f, 0x05,                                            // syscall
                0xc3,                                                  // ret
            };
            Marshal.Copy(stub, 0, RWX, stub.Length);
            return Marshal.GetDelegateForFunctionPointer(RWX, typeof(T)).DynamicInvoke(args);
        }
    }
}
