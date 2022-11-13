using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpAndSimpleHellsGate
{
    /// <summary>
    /// Used to manipulate and extract information from a memory stream.
    /// In this case the memory stream is the NTDLL module.
    /// </summary>
    public class MemoryUtil : IDisposable
    {

        /// <summary>
        /// The memory stream representation of the NTDLL module.
        /// </summary>
        protected Stream ModuleStream { get; set; }

        /// <summary>
        /// Dispose the memory stream when no longer needed.
        /// </summary>
        ~MemoryUtil() => Dispose();

        /// <summary>
        /// Dispose the memory stream when no longer needed.
        /// </summary>
        public void Dispose()
        {
            this.ModuleStream.Dispose();
            this.ModuleStream.Close();
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Extract a structure from the memory stream.
        /// </summary>
        /// <typeparam name="T">The Type of the structure to extract.</typeparam>
        /// <param name="offset">The offset in the memory stream where the structure is located.</param>
        /// <returns>The structure populated or the default structure.</returns>
        protected T GetStructureFromBlob<T>(Int64 offset) where T : struct
        {
            byte[] bytes = this.GetStructureBytesFromOffset<T>(offset);
            if (Marshal.SizeOf(typeof(T)) != bytes.Length)
                return default;

            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T)));
            Marshal.Copy(bytes, 0, ptr, bytes.Length);
            T s = (T)Marshal.PtrToStructure(ptr, typeof(T));

            Marshal.FreeHGlobal(ptr);
            return s;
        }

        /// <summary>
        /// Extract the code from a native Windows function.
        /// </summary>
        /// <param name="offset">The location of the function in the memory stream.</param>
        /// <returns>The 24 bytes representing the code of the function.</returns>
        protected byte[] GetFunctionOpCode(Int64 offset)
        {
            byte[] s = new byte[24];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s, 0, 24);
            return s;
        }

        /// <summary>
        /// Extract a DWORD value from the memory stream.
        /// </summary>
        /// <param name="offset">The location of the DWORD in the memory stream.</param>
        /// <returns>The value of the DWORD.</returns>
        protected UInt32 ReadPtr32(Int64 offset)
        {
            byte[] s = new byte[4];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s, 0, 4);
            return BitConverter.ToUInt32(s, 0);
        }

        /// <summary>
        /// Extract a QWORD value from the memory stream.
        /// </summary>
        /// <param name="offset">The location of the QWORD in the memory stream.</param>
        /// <returns>The value of the QWORD.</returns>
        protected UInt64 ReadPtr64(Int64 offset)
        {
            byte[] s = new byte[8];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s, 0, 8);
            return BitConverter.ToUInt64(s, 0);
        }

        /// <summary>
        /// Extract a WORD value from the memory stream.
        /// </summary>
        /// <param name="offset">The location of the WORD in the memory stream.</param>
        /// <returns>The value of the WORD.</returns>
        protected UInt16 ReadUShort(Int64 offset)
        {
            byte[] s = new byte[2];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s, 0, 2);
            return BitConverter.ToUInt16(s, 0);
        }

        /// <summary>
        /// Extract an ASCII string from the memory stream.
        /// </summary>
        /// <param name="offset">The location of the ASCII string in the memory stream.</param>
        /// <returns>The ASCII string.</returns>
        protected string ReadAscii(Int64 offset)
        {
            int length = 0;
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            while (this.ModuleStream.ReadByte() != 0x00) 
                length++;

            byte[] s = new byte[length];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s, 0, length);
            return Encoding.UTF8.GetString(s);
        }

        /// <summary>
        /// Extract the byte representation of a structure from the memory stream.
        /// </summary>
        /// <typeparam name="T">The Type of the structure to extract from the memory stream.</typeparam>
        /// <param name="offset">The location of the structure in the memory stream.</param>
        /// <returns>The structure as byte span.</returns>
        protected byte[] GetStructureBytesFromOffset<T>(Int64 offset) where T : struct
        {
            byte[] s = new byte[Marshal.SizeOf(typeof(T))];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s, 0, s.Length);
            return s;
        }

        /// <summary>
        /// Get a specific amount of bytes at a specific location in the memory stream.
        /// </summary>
        /// <param name="offset">The location of the bytes to extract from the memory stream.</param>
        /// <param name="size">The number of bytes to extract from the memory stream at a give location.</param>
        /// <returns>The desired bytes as a byte span.</returns>
        protected byte[] GetBytesFromOffset(Int64 offset, int size)
        {
            byte[] s = new byte[size];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s, 0, size);
            return s;
        }
    }
}
