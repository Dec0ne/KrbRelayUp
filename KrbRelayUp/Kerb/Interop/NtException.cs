using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace KrbRelayUp.lib.Interop
{
    public class NtException : Exception
    {
        [DllImport("ntdll.dll")]
        public static extern int RtlNtStatusToDosError(int status);

        internal const int ERROR_MR_MID_NOT_FOUND = 317;

        public NtException(int errorCode) : base(GetErrorMessage(errorCode))
        {
        }

        private static string GetErrorMessage(int errorCode)
        {
            if (KrbRelayUp.Interop.LsaNtStatusToWinError((uint)errorCode) == ERROR_MR_MID_NOT_FOUND)
            {
                return $"NTSTAUTS error code 0x{errorCode.ToString("X")}";
            }
            else
            {
                return $"NTSTATUS error code 0x{errorCode.ToString("X")}: " + (new Win32Exception(errorCode)).Message;
            }
        }
    }
}
