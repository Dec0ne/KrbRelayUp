//    This file is part of OleViewDotNet.
//    Copyright (C) James Forshaw 2014, 2016
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
using System.Runtime.InteropServices;

namespace KrbRelayUp.Relay.Com
{
    [ComImport]
    [Guid("0000000d-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IEnumSTATSTG
    {
        // The user needs to allocate an STATSTG array whose size is celt.
        [PreserveSig]
        int Next(uint celt, [MarshalAs(UnmanagedType.LPArray), Out] System.Runtime.InteropServices.ComTypes.STATSTG[] rgelt, out uint pceltFetched);

        void Skip(uint celt);

        void Reset();

        [return: MarshalAs(UnmanagedType.Interface)]
        IEnumSTATSTG Clone();
    }

    [StructLayout(LayoutKind.Explicit)]
    public class FILETIMEOptional
    {
        [FieldOffset(0)]
        public System.Runtime.InteropServices.ComTypes.FILETIME FileTime;

        [FieldOffset(0)]
        public long QuadPart;

        public FILETIMEOptional(DateTime datetime)
        {
            QuadPart = datetime.ToFileTime();
        }

        public FILETIMEOptional()
        {
        }
    }

    [ComImport, Guid("0000000B-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IStorage
    {
        [return: MarshalAs(UnmanagedType.Interface)]
        IStream CreateStream([In, MarshalAs(UnmanagedType.BStr)] string pwcsName, [In, MarshalAs(UnmanagedType.U4)] STGM grfMode, [In, MarshalAs(UnmanagedType.U4)] int reserved1, [In, MarshalAs(UnmanagedType.U4)] int reserved2);

        [return: MarshalAs(UnmanagedType.Interface)]
        IStream OpenStream([In, MarshalAs(UnmanagedType.BStr)] string pwcsName, IntPtr reserved1, [In, MarshalAs(UnmanagedType.U4)] STGM grfMode, [In, MarshalAs(UnmanagedType.U4)] int reserved2);

        [return: MarshalAs(UnmanagedType.Interface)]
        IStorage CreateStorage([In, MarshalAs(UnmanagedType.BStr)] string pwcsName, [In, MarshalAs(UnmanagedType.U4)] STGM grfMode, [In, MarshalAs(UnmanagedType.U4)] int reserved1, [In, MarshalAs(UnmanagedType.U4)] int reserved2);

        [return: MarshalAs(UnmanagedType.Interface)]
        IStorage OpenStorage([In, MarshalAs(UnmanagedType.BStr)] string pwcsName, IntPtr pstgPriority, [In, MarshalAs(UnmanagedType.U4)] STGM grfMode, IntPtr snbExclude, [In, MarshalAs(UnmanagedType.U4)] int reserved);

        void CopyTo(int ciidExclude, [In, MarshalAs(UnmanagedType.LPArray)] Guid[] pIIDExclude, IntPtr snbExclude, [In, MarshalAs(UnmanagedType.Interface)] IStorage stgDest);

        void MoveElementTo([In, MarshalAs(UnmanagedType.BStr)] string pwcsName, [In, MarshalAs(UnmanagedType.Interface)] IStorage stgDest, [In, MarshalAs(UnmanagedType.BStr)] string pwcsNewName, [In, MarshalAs(UnmanagedType.U4)] int grfFlags);

        void Commit(int grfCommitFlags);

        void Revert();

        void EnumElements([In, MarshalAs(UnmanagedType.U4)] int reserved1, IntPtr reserved2, [In, MarshalAs(UnmanagedType.U4)] int reserved3, [MarshalAs(UnmanagedType.Interface)] out IEnumSTATSTG ppVal);

        void DestroyElement([In, MarshalAs(UnmanagedType.BStr)] string pwcsName);

        void RenameElement([In, MarshalAs(UnmanagedType.BStr)] string pwcsOldName, [In, MarshalAs(UnmanagedType.BStr)] string pwcsNewName);

        void SetElementTimes([In, MarshalAs(UnmanagedType.BStr)] string pwcsName, [In] FILETIMEOptional pctime, [In] FILETIMEOptional patime, [In] FILETIMEOptional pmtime);

        void SetClass([In] ref Guid clsid);

        void SetStateBits(int grfStateBits, int grfMask);

        void Stat(out System.Runtime.InteropServices.ComTypes.STATSTG pStatStg, int grfStatFlag);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct CATEGORYINFO
    {
        public Guid catid;
        public int lcid;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szDescription;
    }

    [Guid("0002E011-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IEnumCATEGORYINFO
    {
        int Next(
            int celt,
            [Out] CATEGORYINFO[] rgelt,
            out int pceltFetched);

        int Skip(int celt);

        int Reset();

        int Clone(out IEnumCATEGORYINFO ppenum);
    }
}