using KrbRelayUp.Relay.Com;
using System;
using System.Runtime.InteropServices;

namespace KrbRelayUp.Relay
{
    [Guid("0000033C-0000-0000-c000-000000000046")]
    [ComImport]
    public class StandardActivator
    {
    }

    internal enum RUNLEVEL : uint
    {
        RUNLEVEL_LUA = 0x0,
        RUNLEVEL_HIGHEST = 0x1,
        RUNLEVEL_ADMIN = 0x2,
        RUNLEVEL_MAX_NON_UIA = 0x3,
        RUNLEVEL_LUA_UIA = 0x10,
        RUNLEVEL_HIGHEST_UIA = 0x11,
        RUNLEVEL_ADMIN_UIA = 0x12,
        RUNLEVEL_MAX = 0x13,
        INVALID_LUA_RUNLEVEL = 0xFFFFFFFF,
    };

    internal enum PRT
    {
        PRT_IGNORE = 0x0,
        PRT_CREATE_NEW = 0x1,
        PRT_USE_THIS = 0x2,
        PRT_USE_THIS_ONLY = 0x3,
    };

    [Guid("000001B9-0000-0000-c000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface ISpecialSystemPropertiesActivator
    {
        void SetSessionId(int dwSessionId, int bUseConsole, int fRemoteThisSessionId);

        void GetSessionId(out int pdwSessionId, out int pbUseConsole);

        void GetSessionId2(out int pdwSessionId, out int pbUseConsole, out int pfRemoteThisSessionId);

        void SetClientImpersonating(int fClientImpersonating);

        void GetClientImpersonating(out int pfClientImpersonating);

        void SetPartitionId(ref Guid guidPartition);

        void GetPartitionId(out Guid pguidPartition);

        void SetProcessRequestType(PRT dwPRT);

        void GetProcessRequestType(out PRT pdwPRT);

        void SetOrigClsctx(int dwOrigClsctx);

        void GetOrigClsctx(out int pdwOrigClsctx);

        void GetDefaultAuthenticationLevel(out int pdwDefaultAuthnLvl);

        void SetDefaultAuthenticationLevel(int dwDefaultAuthnLvl);

        void GetLUARunLevel(out RUNLEVEL pdwLUARunLevel, out IntPtr phwnd);

        void SetLUARunLevel(RUNLEVEL dwLUARunLevel, IntPtr hwnd);
    }

    [Guid("000001B8-0000-0000-c000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IStandardActivator
    {
        void StandardGetClassObject(in Guid rclsid, CLSCTX dwContext, [In] COSERVERINFO pServerInfo, in Guid riid, [MarshalAs(UnmanagedType.IUnknown)] out object ppvClassObj);

        void StandardCreateInstance(in Guid Clsid, IntPtr punkOuter, CLSCTX dwClsCtx, [In] COSERVERINFO pServerInfo, int dwCount, [In, Out][MarshalAs(UnmanagedType.LPArray)] MULTI_QI[] pResults);

        void StandardGetInstanceFromFile([In] COSERVERINFO pServerInfo, in Guid pclsidOverride,
            IntPtr punkOuter, CLSCTX dwClsCtx, int grfMode, [MarshalAs(UnmanagedType.LPWStr)] string pwszName, int dwCount, [In, Out][MarshalAs(UnmanagedType.LPArray)] MULTI_QI[] pResults);

        int StandardGetInstanceFromIStorage(
            [In] COSERVERINFO pServerInfo,
            in Guid pclsidOverride,
            IntPtr punkOuter,
            CLSCTX dwClsCtx,
            IStorage pstg,
            int dwCount,
            [In, Out][MarshalAs(UnmanagedType.LPArray)] Ole32.MULTI_QI[] pResults);

        int StandardGetInstanceFromIStoragee(
            COSERVERINFO pServerInfo,
            ref Guid pclsidOverride,
            [MarshalAs(UnmanagedType.IUnknown)] object pUnkOuter,
            CLSCTX dwClsCtx,
            IStorage pstg,
            int dwCount,
            [In, Out][MarshalAs(UnmanagedType.LPArray)] Ole32.MULTI_QI[] pResults);

        void Reset();
    }

}