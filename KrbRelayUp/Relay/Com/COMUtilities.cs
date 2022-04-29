//    This file is part of OleViewDotNet.
//    Copyright (C) James Forshaw 2014
//
//    OleViewDotNet is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    OleViewDotNet is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with OleViewDotNet.  If not, see <http://www.gnu.org/licenses/>.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

//using System.Windows.Forms;

namespace KrbRelayUp.Relay.Com
{
    internal class TypeLibCallback
    {
        public void ReportEvent(ImporterEventKind eventKind, int eventCode, string eventMsg)
        {
            if ((eventKind == ImporterEventKind.NOTIF_TYPECONVERTED) && (_progress != null))
            {
                _progress.Report(new Tuple<string, int>(eventMsg, -1));
            }
        }

        public TypeLibCallback(IProgress<Tuple<string, int>> progress)
        {
            _progress = progress;
        }

        private IProgress<Tuple<string, int>> _progress;
    }

    public class RegistryValue
    {
        public string Name { get; }
        public object Value { get; }

        internal RegistryValue(string name, object value)
        {
            Name = name;
            Value = value ?? string.Empty;
        }
    }

    [Flags]
    public enum CLSCTX : uint
    {
        INPROC_SERVER = 0x1,
        INPROC_HANDLER = 0x2,
        LOCAL_SERVER = 0x4,
        INPROC_SERVER16 = 0x8,
        REMOTE_SERVER = 0x10,
        INPROC_HANDLER16 = 0x20,
        RESERVED1 = 0x40,
        RESERVED2 = 0x80,
        RESERVED3 = 0x100,
        RESERVED4 = 0x200,
        NO_CODE_DOWNLOAD = 0x400,
        RESERVED5 = 0x800,
        NO_CUSTOM_MARSHAL = 0x1000,
        ENABLE_CODE_DOWNLOAD = 0x2000,
        NO_FAILURE_LOG = 0x4000,
        DISABLE_AAA = 0x8000,
        ENABLE_AAA = 0x10000,
        FROM_DEFAULT_CONTEXT = 0x20000,
        ACTIVATE_32_BIT_SERVER = 0x40000,
        ACTIVATE_64_BIT_SERVER = 0x80000,
        ENABLE_CLOAKING = 0x100000,
        APPCONTAINER = 0x400000,
        ACTIVATE_AAA_AS_IU = 0x800000,
        ACTIVATE_NATIVE_SERVER = 0x1000000,
        ACTIVATE_ARM32_SERVER = 0x2000000,
        PS_DLL = 0x80000000,
        SERVER = INPROC_SERVER | LOCAL_SERVER | REMOTE_SERVER,
        ALL = INPROC_SERVER | INPROC_HANDLER | LOCAL_SERVER | REMOTE_SERVER
    }

    [Flags]
    public enum REGCLS
    {
        SINGLEUSE = 0,
        MULTIPLEUSE = 1,
        MULTI_SEPARATE = 2,
        SUSPENDED = 4,
        SURROGATE = 8,
        AGILE = 0x10,
    }

    [Flags]
    public enum STGM
    {
        READ = 0x00000000,
        WRITE = 0x00000001,
        READWRITE = 0x00000002,
        SHARE_DENY_NONE = 0x00000040,
        SHARE_DENY_READ = 0x00000030,
        SHARE_DENY_WRITE = 0x00000020,
        SHARE_EXCLUSIVE = 0x00000010,
        PRIORITY = 0x00040000,
        CREATE = 0x00001000,
        CONVERT = 0x00020000,
        FAILIFTHERE = READ,
        DIRECT = READ,
        TRANSACTED = 0x00010000,
        NOSCRATCH = 0x00100000,
        NOSNAPSHOT = 0x00200000,
        SIMPLE = 0x08000000,
        DIRECT_SWMR = 0x00400000,
        DELETEONRELEASE = 0x04000000
    }


    public enum RPC_AUTHN_LEVEL
    {
        DEFAULT = 0,
        NONE = 1,
        CONNECT = 2,
        CALL = 3,
        PKT = 4,
        PKT_INTEGRITY = 5,
        PKT_PRIVACY = 6,
    }

    public enum RPC_IMP_LEVEL
    {
        DEFAULT = 0,
        ANONYMOUS = 1,
        IDENTIFY = 2,
        IMPERSONATE = 3,
        DELEGATE = 4,
    }


    public enum MSHCTX
    {
        LOCAL = 0,
        NOSHAREDMEM = 1,
        DIFFERENTMACHINE = 2,
        INPROC = 3,
        CROSSCTX = 4,
        RESERVED1 = 5,
    }

    public enum MSHLFLAGS
    {
        NORMAL = 0,
        TABLESTRONG = 1,
        TABLEWEAK = 2,
        NOPING = 4
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct OptionalGuid : IDisposable
    {
        private IntPtr pGuid;

        void IDisposable.Dispose()
        {
            if (pGuid != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(pGuid);
                pGuid = IntPtr.Zero;
            }
        }

        public OptionalGuid(Guid guid)
        {
            pGuid = Marshal.AllocCoTaskMem(16);
            Marshal.Copy(guid.ToByteArray(), 0, pGuid, 16);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MULTI_QI : IDisposable
    {
        private OptionalGuid pIID;
        private IntPtr pItf;
        private int hr;

        public object GetObject()
        {
            if (pItf == IntPtr.Zero)
            {
                return null;
            }
            else
            {
                return Marshal.GetObjectForIUnknown(pItf);
            }
        }

        public IntPtr GetObjectPointer()
        {
            if (pItf != IntPtr.Zero)
            {
                Marshal.AddRef(pItf);
            }
            return pItf;
        }

        public int HResult()
        {
            return hr;
        }

        void IDisposable.Dispose()
        {
            ((IDisposable)pIID).Dispose();
            if (pItf != IntPtr.Zero)
            {
                Marshal.Release(pItf);
                pItf = IntPtr.Zero;
            }
        }

        public MULTI_QI(Guid iid)
        {
            pIID = new OptionalGuid(iid);
            pItf = IntPtr.Zero;
            hr = 0;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public sealed class COSERVERINFO : IDisposable
    {
        private int dwReserved1;

        [MarshalAs(UnmanagedType.LPWStr)]
        private string pwszName;

        private IntPtr pAuthInfo;
        private int dwReserved2;

        void IDisposable.Dispose()
        {
            if (pAuthInfo != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(pAuthInfo);
            }
        }

        public COSERVERINFO(string name)
        {
            pwszName = name;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public class BIND_OPTS3
    {
        private int cbStruct;
        public int grfFlags;
        public int grfMode;
        public int dwTickCountDeadline;
        public int dwTrackFlags;
        public CLSCTX dwClassContext;
        public int locale;
        public IntPtr pServerInfo;
        public IntPtr hwnd;

        public BIND_OPTS3()
        {
            cbStruct = Marshal.SizeOf(this);
        }
    }

    public static class COMUtilities
    {
        private enum RegKind
        {
            RegKind_Default = 0,
            RegKind_Register = 1,
            RegKind_None = 2
        }

        internal static byte[] ReadAll(this BinaryReader reader, int length)
        {
            byte[] ret = reader.ReadBytes(length);
            if (ret.Length != length)
            {
                throw new EndOfStreamException();
            }
            return ret;
        }

        internal static Guid ReadGuid(this BinaryReader reader)
        {
            return new Guid(reader.ReadAll(16));
        }

        internal static char ReadUnicodeChar(this BinaryReader reader)
        {
            return BitConverter.ToChar(reader.ReadAll(2), 0);
        }

        internal static void Write(this BinaryWriter writer, Guid guid)
        {
            writer.Write(guid.ToByteArray());
        }

        internal static string ReadZString(this BinaryReader reader)
        {
            StringBuilder builder = new StringBuilder();
            char ch = reader.ReadUnicodeChar();
            while (ch != 0)
            {
                builder.Append(ch);
                ch = reader.ReadUnicodeChar();
            }
            return builder.ToString();
        }

        internal static void WriteZString(this BinaryWriter writer, string str)
        {
            writer.Write(Encoding.Unicode.GetBytes(str + "\0"));
        }

        private static string GetNextToken(string name, out string token)
        {
            token = null;
            if (name.Length == 0)
            {
                return name;
            }
            int end_index = name.IndexOf('_');
            if (end_index < 0)
            {
                token = name;
            }
            else
            {
                token = name.Substring(0, end_index);
            }
            return name.Substring(end_index + 1).TrimStart('_');
        }

        private static string GetNextToken(string name, out int token)
        {
            if (name.Length == 0 || !char.IsDigit(name[0]))
            {
                throw new InvalidDataException("Expected an integer");
            }
            int length = 0;
            while (char.IsDigit(name[length]))
            {
                length++;
            }

            token = int.Parse(name.Substring(0, length));

            return name.Substring(length).TrimStart('_');
        }

        private static string ReadType(ref string name)
        {
            string token;
            name = GetNextToken(name, out token);
            if (String.IsNullOrEmpty(token))
            {
                throw new InvalidDataException("Expected a type name");
            }

            if (char.IsLetter(token[0]))
            {
                return token;
            }
            else if (token[0] == '~')
            {
                StringBuilder builder = new StringBuilder();
                int type_count;

                name = GetNextToken(name, out type_count);
                builder.Append(token.Substring(1));
                builder.Append("<");
                List<string> types = new List<string>();
                for (int i = 0; i < type_count; ++i)
                {
                    types.Add(ReadType(ref name));
                }
                builder.Append(String.Join(",", types));
                builder.Append(">");
                return builder.ToString();
            }
            else
            {
                throw new InvalidDataException("Expected a type name or a generic type");
            }
        }

        private class ReportQueryProgress
        {
            private int _total_count;
            private int _current;
            private IProgress<Tuple<string, int>> _progress;

            private const int MINIMUM_REPORT_SIZE = 25;

            public ReportQueryProgress(IProgress<Tuple<string, int>> progress, int total_count)
            {
                _total_count = total_count;
                _progress = progress;
            }

            public void Report()
            {
                int current = Interlocked.Increment(ref _current);
                if ((current % MINIMUM_REPORT_SIZE) == 1)
                {
                    _progress.Report(new Tuple<string, int>($"Querying Interfaces: {current} of {_total_count}",
                        (100 * current) / _total_count));
                }
            }
        }

        internal static int GetProcessIdFromIPid(Guid ipid)
        {
            return BitConverter.ToUInt16(ipid.ToByteArray(), 4);
        }

        internal static int GetApartmentIdFromIPid(Guid ipid)
        {
            return BitConverter.ToInt16(ipid.ToByteArray(), 6);
        }

        internal static string GetApartmentIdStringFromIPid(Guid ipid)
        {
            int appid = GetApartmentIdFromIPid(ipid);
            switch (appid)
            {
                case 0:
                    return "NTA";

                case -1:
                    return "MTA";

                default:
                    return $"STA (Thread ID {appid})";
            }
        }

        private static Dictionary<string, Assembly> _cached_reflection_assemblies = new Dictionary<string, Assembly>();

        private static Assembly ResolveAssembly(string base_path, string name)
        {
            if (_cached_reflection_assemblies.ContainsKey(name))
            {
                return _cached_reflection_assemblies[name];
            }

            Assembly asm = null;
            if (name.Contains(","))
            {
                asm = Assembly.ReflectionOnlyLoad(name);
            }
            else
            {
                string full_path = Path.Combine(base_path, $"{name}.winmd");
                if (File.Exists(full_path))
                {
                    asm = Assembly.ReflectionOnlyLoadFrom(full_path);
                }
                else
                {
                    int last_index = name.LastIndexOf('.');
                    if (last_index < 0)
                    {
                        return null;
                    }
                    asm = ResolveAssembly(base_path, name.Substring(0, last_index));
                }
            }

            _cached_reflection_assemblies[name] = asm;
            return _cached_reflection_assemblies[name];
        }

        public static string GetProcessNameById(int pid)
        {
            try
            {
                return Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                return string.Empty;
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint InspectHStringCallback2(IntPtr context, long readAddress, int length, IntPtr buffer);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint InspectHStringCallback(IntPtr context, IntPtr readAddress, int length, IntPtr buffer);


        internal static readonly bool IsWindows81OrLess = Environment.OSVersion.Version < new Version(6, 4);
        internal static readonly bool IsWindows10RS2OrLess = Environment.OSVersion.Version < new Version(10, 0, 16299);
        internal static readonly bool IsWindows10RS3OrLess = Environment.OSVersion.Version < new Version(10, 0, 17134);
        internal static readonly bool IsWindows10RS4OrLess = Environment.OSVersion.Version < new Version(10, 0, 17763);
        internal static readonly bool IsWindows101909OrLess = Environment.OSVersion.Version < new Version(10, 0, 19041);

    
    }
}