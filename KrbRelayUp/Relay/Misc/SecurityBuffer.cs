using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace KrbRelayUp.Relay
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct SspiHandle
    {
        // private fields
        private IntPtr _hi;

        private IntPtr _low;

        // public properties
        /// <summary>
        /// Gets a value indicating whether this instance is zero.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is zero; otherwise, <c>false</c>.
        /// </value>
        public bool IsZero
        {
            get
            {
                if (_hi != IntPtr.Zero)
                {
                    return false;
                }
                else
                {
                    return _low == IntPtr.Zero;
                }
            }
        }

        // public methods
        /// <summary>
        /// Sets to invalid.
        /// </summary>
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public void SetToInvalid()
        {
            _hi = IntPtr.Zero;
            _low = IntPtr.Zero;
        }
    }

    /// <summary>
    /// A SecBufferDesc structure.
    /// </summary>
    /// <remarks>
    /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa379815(v=vs.85).aspx
    /// </remarks>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityBufferDescriptor : IDisposable
    {
        // public fields
        public SecurityBufferType BufferType;

        public int NumBuffers;
        public IntPtr BufferPtr; //Point to SecBuffer

        // constructors
        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityBufferDescriptor" /> struct.
        /// </summary>
        /// <param name="bufferSize">Size of the buffer.</param>
        public SecurityBufferDescriptor(int bufferSize)
        {
            BufferType = SecurityBufferType.Version;
            NumBuffers = 1;
            var buffer = new SecurityBuffer(bufferSize);
            BufferPtr = Marshal.AllocHGlobal(Marshal.SizeOf(buffer));
            Marshal.StructureToPtr(buffer, BufferPtr, false);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityBufferDescriptor" /> struct.
        /// </summary>
        /// <param name="secBufferBytes">The sec buffer bytes.</param>
        public SecurityBufferDescriptor(byte[] secBufferBytes)
        {
            BufferType = SecurityBufferType.Version;
            NumBuffers = 1;
            var buffer = new SecurityBuffer(secBufferBytes);
            BufferPtr = Marshal.AllocHGlobal(Marshal.SizeOf(buffer));
            Marshal.StructureToPtr(buffer, BufferPtr, false);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityBufferDescriptor" /> struct.
        /// </summary>
        /// <param name="buffers">The buffers.</param>
        /// <exception cref="System.ArgumentException">cannot be null or 0 length;buffers</exception>
        public SecurityBufferDescriptor(SecurityBuffer[] buffers)
        {
            if (buffers == null || buffers.Length == 0)
            {
                throw new ArgumentException("cannot be null or 0 length", "buffers");
            }

            BufferType = SecurityBufferType.Version;
            NumBuffers = buffers.Length;

            //Allocate memory for SecBuffer Array....
            BufferPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecurityBuffer)) * NumBuffers);

            for (int i = 0; i < buffers.Length; i++)
            {
                var currentBuffer = buffers[i];
                var currentOffset = i * Marshal.SizeOf(typeof(SecurityBuffer));
                Marshal.WriteInt32(BufferPtr, currentOffset, currentBuffer.Count);

                var length = currentOffset + Marshal.SizeOf(typeof(int));
                Marshal.WriteInt32(BufferPtr, length, (int)currentBuffer.BufferType);

                length = currentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int));
                Marshal.WriteIntPtr(BufferPtr, length, currentBuffer.Token);
            }
        }

        // public methods
        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            if (BufferPtr != IntPtr.Zero)
            {
                if (NumBuffers == 1)
                {
                    var buffer = (SecurityBuffer)Marshal.PtrToStructure(BufferPtr, typeof(SecurityBuffer));
                    buffer.Dispose();
                }
                else
                {
                    // Since we aren't sending any messages using the kerberos encrypt/decrypt.
                    // The 1st buffer is going to be empty. We can skip it.
                    for (int i = 1; i < NumBuffers; i++)
                    {
                        var currentOffset = i * Marshal.SizeOf(typeof(SecurityBuffer));
                        var totalLength = currentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int));
                        var buffer = Marshal.ReadIntPtr(BufferPtr, totalLength);
                        Marshal.FreeHGlobal(buffer);
                    }
                }

                Marshal.FreeHGlobal(BufferPtr);
                BufferPtr = IntPtr.Zero;
            }
        }

        /// <summary>
        /// To the byte array.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="System.InvalidOperationException">Object has already been disposed!!!</exception>
        public byte[] ToByteArray()
        {
            byte[] bytes = null;

            if (BufferPtr == IntPtr.Zero)
            {
                throw new InvalidOperationException("Object has already been disposed!!!");
            }

            if (NumBuffers == 1)
            {
                var buffer = (SecurityBuffer)Marshal.PtrToStructure(BufferPtr, typeof(SecurityBuffer));

                if (buffer.Count > 0)
                {
                    bytes = new byte[buffer.Count];
                    Marshal.Copy(buffer.Token, bytes, 0, buffer.Count);
                }
            }
            else
            {
                var bytesToAllocate = 0;

                for (int i = 0; i < NumBuffers; i++)
                {
                    var currentOffset = i * Marshal.SizeOf(typeof(SecurityBuffer));
                    bytesToAllocate += Marshal.ReadInt32(BufferPtr, currentOffset);
                }

                bytes = new byte[bytesToAllocate];

                for (int i = 0, bufferIndex = 0; i < NumBuffers; i++)
                {
                    var currentOffset = i * Marshal.SizeOf(typeof(SecurityBuffer));
                    var bytesToCopy = Marshal.ReadInt32(BufferPtr, currentOffset);
                    var length = currentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int));
                    IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(BufferPtr, length);
                    Marshal.Copy(SecBufferpvBuffer, bytes, bufferIndex, bytesToCopy);
                    bufferIndex += bytesToCopy;
                }
            }

            return (bytes);
        }
    }

    internal enum SecurityBufferType
    {
        /// <summary>
        /// SECBUFFER_VERSION
        /// </summary>
        Version = 0,

        /// <summary>
        /// SECBUFFER_EMPTY
        /// </summary>
        Empty = 0,

        /// <summary>
        /// SECBUFFER_DATA
        /// </summary>
        Data = 1,

        /// <summary>
        /// SECBUFFER_TOKEN
        /// </summary>
        Token = 2,

        /// <summary>
        /// SECBUFFER_PADDING
        /// </summary>
        Padding = 9,

        /// <summary>
        /// SECBUFFER_STREAM
        /// </summary>
        Stream = 10
    }

    /// <summary>
    /// A SecBuffer structure.
    /// </summary>
    /// <remarks>
    /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa379814(v=vs.85).aspx
    /// </remarks>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityBuffer : IDisposable
    {
        // public fields
        public int Count;

        public SecurityBufferType BufferType;
        public IntPtr Token;

        // constructors
        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityBuffer" /> struct.
        /// </summary>
        /// <param name="bufferSize">Size of the buffer.</param>
        public SecurityBuffer(int bufferSize)
        {
            Count = bufferSize;
            BufferType = SecurityBufferType.Token;
            Token = Marshal.AllocHGlobal(bufferSize);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityBuffer" /> struct.
        /// </summary>
        /// <param name="bytes">The bytes.</param>
        public SecurityBuffer(byte[] bytes)
        {
            Count = bytes.Length;
            BufferType = SecurityBufferType.Token;
            Token = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, Token, bytes.Length);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityBuffer" /> struct.
        /// </summary>
        /// <param name="bytes">The bytes.</param>
        /// <param name="bufferType">Type of the buffer.</param>
        public SecurityBuffer(byte[] bytes, SecurityBufferType bufferType)
        {
            BufferType = bufferType;

            if (bytes != null && bytes.Length != 0)
            {
                Count = bytes.Length;
                Token = Marshal.AllocHGlobal(Count);
                Marshal.Copy(bytes, 0, Token, Count);
            }
            else
            {
                Count = 0;
                Token = IntPtr.Zero;
            }
        }

        // public methods
        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            if (Token != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Token);
                Token = IntPtr.Zero;
            }
        }
    }
}
