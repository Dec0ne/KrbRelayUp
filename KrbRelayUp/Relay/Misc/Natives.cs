using System;
using System.Runtime.InteropServices;
using System.Text;

namespace KrbRelayUp.Relay
{
    internal class Natives
    {
        public enum WTS_INFO_CLASS
        {
            InitialProgram = 0,
            ApplicationName = 1,
            WorkingDirectory = 2,
            OEMId = 3,
            SessionId = 4,
            UserName = 5,
            WinStationName = 6,
            DomainName = 7,
            ConnectState = 8,
            ClientBuildNumber = 9,
            ClientName = 10,
            ClientDirectory = 11,
            ClientProductId = 12,
            ClientHardwareId = 13,
            ClientAddress = 14,
            ClientDisplay = 15,
            ClientProtocolType = 16
        }

        public enum WTS_CONNECTSTATE_CLASS
        {
            Active,
            Connected,
            ConnectQuery,
            Shadow,
            Disconnected,
            Idle,
            Listen,
            Reset,
            Down,
            Init
        }

        public enum NTStatus : uint
        {
            STATUS_SUCCESS = 0x00000000,
            STATUS_PENDING = 0x00000103,
            STATUS_NOTIFY_CLEANUP = 0x0000010B,
            STATUS_NOTIFY_ENUM_DIR = 0x0000010C,
            SEC_I_CONTINUE_NEEDED = 0x00090312,
            STATUS_OBJECT_NAME_EXISTS = 0x40000000,
            STATUS_BUFFER_OVERFLOW = 0x80000005,
            STATUS_NO_MORE_FILES = 0x80000006,
            SEC_E_SECPKG_NOT_FOUND = 0x80090305,
            SEC_E_INVALID_TOKEN = 0x80090308,
            STATUS_NOT_IMPLEMENTED = 0xC0000002,
            STATUS_INVALID_INFO_CLASS = 0xC0000003,
            STATUS_INFO_LENGTH_MISMATCH = 0xC0000004,
            STATUS_INVALID_HANDLE = 0xC0000008,
            STATUS_INVALID_PARAMETER = 0xC000000D,
            STATUS_NO_SUCH_DEVICE = 0xC000000E,
            STATUS_NO_SUCH_FILE = 0xC000000F,
            STATUS_INVALID_DEVICE_REQUEST = 0xC0000010,
            STATUS_END_OF_FILE = 0xC0000011,
            STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016,
            STATUS_ACCESS_DENIED = 0xC0000022, // The user is not authorized to access the resource.
            STATUS_BUFFER_TOO_SMALL = 0xC0000023,
            STATUS_OBJECT_NAME_INVALID = 0xC0000033,
            STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034,
            STATUS_OBJECT_NAME_COLLISION = 0xC0000035, // The file already exists
            STATUS_OBJECT_PATH_INVALID = 0xC0000039,
            STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A, // The share path does not reference a valid resource.
            STATUS_OBJECT_PATH_SYNTAX_BAD = 0xC000003B,
            STATUS_DATA_ERROR = 0xC000003E, // IO error
            STATUS_SHARING_VIOLATION = 0xC0000043,
            STATUS_FILE_LOCK_CONFLICT = 0xC0000054,
            STATUS_LOCK_NOT_GRANTED = 0xC0000055,
            STATUS_DELETE_PENDING = 0xC0000056,
            STATUS_PRIVILEGE_NOT_HELD = 0xC0000061,
            STATUS_WRONG_PASSWORD = 0xC000006A,
            STATUS_LOGON_FAILURE = 0xC000006D, // Authentication failure.
            STATUS_ACCOUNT_RESTRICTION = 0xC000006E, // The user has an empty password, which is not allowed
            STATUS_INVALID_LOGON_HOURS = 0xC000006F,
            STATUS_INVALID_WORKSTATION = 0xC0000070,
            STATUS_PASSWORD_EXPIRED = 0xC0000071,
            STATUS_ACCOUNT_DISABLED = 0xC0000072,
            STATUS_RANGE_NOT_LOCKED = 0xC000007E,
            STATUS_DISK_FULL = 0xC000007F,
            STATUS_INSUFFICIENT_RESOURCES = 0xC000009A,
            STATUS_MEDIA_WRITE_PROTECTED = 0xC00000A2,
            STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA,
            STATUS_NOT_SUPPORTED = 0xC00000BB,
            STATUS_NETWORK_NAME_DELETED = 0xC00000C9,
            STATUS_BAD_DEVICE_TYPE = 0xC00000CB,
            STATUS_BAD_NETWORK_NAME = 0xC00000CC,
            STATUS_TOO_MANY_SESSIONS = 0xC00000CE,
            STATUS_DIRECTORY_NOT_EMPTY = 0xC0000101,
            STATUS_NOT_A_DIRECTORY = 0xC0000103,
            STATUS_TOO_MANY_OPENED_FILES = 0xC000011F,
            STATUS_CANCELLED = 0xC0000120,
            STATUS_CANNOT_DELETE = 0xC0000121,
            STATUS_FILE_CLOSED = 0xC0000128,
            STATUS_LOGON_TYPE_NOT_GRANTED = 0xC000015B,
            STATUS_ACCOUNT_EXPIRED = 0xC0000193,
            STATUS_FS_DRIVER_REQUIRED = 0xC000019C,
            STATUS_USER_SESSION_DELETED = 0xC0000203,
            STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205,
            STATUS_NOT_FOUND = 0xC0000225,
            STATUS_ACCOUNT_LOCKED_OUT = 0xC0000234,
            STATUS_PASSWORD_MUST_CHANGE = 0xC0000224,
            STATUS_NOT_A_REPARSE_POINT = 0xC0000275,

            STATUS_INVALID_SMB = 0x00010002,        // SMB1/CIFS: A corrupt or invalid SMB request was received
            STATUS_SMB_BAD_COMMAND = 0x00160002,    // SMB1/CIFS: An unknown SMB command code was received by the server
            STATUS_SMB_BAD_FID = 0x00060001,        // SMB1/CIFS
            STATUS_SMB_BAD_TID = 0x00050002,        // SMB1/CIFS
            STATUS_OS2_INVALID_ACCESS = 0x000C0001, // SMB1/CIFS
            STATUS_OS2_NO_MORE_SIDS = 0x00710001,   // SMB1/CIFS
            STATUS_OS2_INVALID_LEVEL = 0x007C0001,  // SMB1/CIFS
        }

        [DllImport("wldap32", EntryPoint = "ldap_set_option", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ldap_set_option(IntPtr ld, uint option, ref uint invalue);

        [DllImport("wldap32", EntryPoint = "ldap_set_option", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ldap_set_option(IntPtr ld, uint option, IntPtr pointer);

        [DllImport("wldap32", EntryPoint = "ldap_connect", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern uint ldap_connect(IntPtr ld, LDAP_TIMEVAL timeout);

        [DllImport("wldap32", EntryPoint = "ldap_initA", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr ldap_init(string hostname, uint port);

        [DllImport("wldap32", EntryPoint = "ldap_sasl_bind_sA", CharSet = CharSet.Ansi)]
        public static extern int ldap_sasl_bind(
            [In] IntPtr ld,
            string dn, string mechanism,
            IntPtr cred,
            IntPtr serverctrls,
            IntPtr clientctrls,
            out IntPtr msgidp);

        [StructLayout(LayoutKind.Sequential)]
        internal sealed class berval
        {
            public int bv_len;
            public IntPtr bv_val = IntPtr.Zero;

            public berval()
            { }
        }

        [DllImport("wldap32", EntryPoint = "ldap_get_optionW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ldap_get_option(IntPtr ld, int option, out int value);

        [DllImport("wldap32", EntryPoint = "ldap_searchW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ldap_search(
            IntPtr ld,
            string @base,
            int scope,
            string filter,
            IntPtr attrs,
            int attrsonly);

        [StructLayout(LayoutKind.Sequential)]
        public sealed class LDAP_TIMEVAL
        {
            public int tv_sec;
            public int tv_usec;
        }

        [DllImport("wldap32", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ldap_result(
            IntPtr ld,
            int msgid,
            int all,
            LDAP_TIMEVAL timeout,
            ref IntPtr pMessage);

        [DllImport("wldap32", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_first_entry(
            IntPtr ld,
            IntPtr pMessage);

        [DllImport("wldap32", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_next_entry(
            IntPtr ld,
            IntPtr pMessage);

        [DllImport("wldap32", EntryPoint = "ldap_get_dnW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_get_dn(IntPtr ld, IntPtr message);

        [DllImport("wldap32", EntryPoint = "ldap_first_attributeW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_first_attribute(IntPtr ld, IntPtr entry, ref IntPtr ppBer);

        [DllImport("wldap32", EntryPoint = "ldap_next_attributeW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_next_attribute(IntPtr ld, IntPtr entry, ref IntPtr ppBer);

        [DllImport("wldap32", EntryPoint = "ldap_next_attributeW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_next_attribute(IntPtr ld, IntPtr entry, IntPtr ppBer);

        [DllImport("wldap32", EntryPoint = "ldap_get_values_lenW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_get_values_len(IntPtr ld, IntPtr entry, IntPtr pBer);

        [DllImport("wldap32", EntryPoint = "ldap_modify_s", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ldap_modify_s(IntPtr ld, string dn, IntPtr mods);

        [DllImport("wldap32")]
        internal static extern int ldap_unbind(IntPtr ld);

        [DllImport("wldap32", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ldap_value_free_len(IntPtr vals);

        [DllImport("Wtsapi32.dll")]
        public static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, WTS_INFO_CLASS wtsInfoClass, out IntPtr ppBuffer, out uint pBytesReturned);

        [DllImport("advapi32.dll", EntryPoint = "SystemFunction018", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern NTStatus RtlEncryptNtOwfPwdWithNtSesKey([In] byte[] ntOwfPassword, [In] ref byte[] sessionkey, [In, Out] byte[] encryptedNtOwfPassword);

        [DllImport("advapi32.dll", EntryPoint = "SystemFunction018", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern NTStatus RtlEncryptNtOwfPwdWithNtSesKey([In] byte[] ntOwfPassword, [In] byte[] sessionkey, [In, Out] byte[] encryptedNtOwfPassword);

        internal static NTStatus RtlEncryptNtOwfPwdWithNtSesKey(byte[] ntOwfPassword, byte[] sessionkey, out byte[] encryptedNtOwfPassword)
        {
            encryptedNtOwfPassword = new byte[16];
            return RtlEncryptNtOwfPwdWithNtSesKey(ntOwfPassword, ref sessionkey, encryptedNtOwfPassword);
        }

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int AcquireCredentialsHandle(
                   string pszPrincipal, //SEC_CHAR*
                   string pszPackage, //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
                   int fCredentialUse,
                   IntPtr PAuthenticationID,//_LUID AuthenticationID,//pvLogonID,//PLUID
                   IntPtr pAuthData,//PVOID
                   IntPtr pGetKeyFn, //SEC_GET_KEY_FN
                   IntPtr pvGetKeyArgument, //PVOID
                   ref SECURITY_HANDLE phCredential, //SecHandle //PCtxtHandle ref
                   IntPtr ptsExpiry  //PTimeStamp //TimeStamp ref
               );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        public static extern SecStatusCode AcceptSecurityContext(
            [In] SecHandle phCredential,
            [In] SecHandle phContext,
            [In] SecurityBufferDescriptor pInput,
            AcceptContextReqFlags fContextReq,
            SecDataRep TargetDataRep,
            [In, Out] SecHandle phNewContext,
            [In, Out] SecurityBufferDescriptor pOutput,
            out AcceptContextRetFlags pfContextAttr,
            [Out] SECURITY_INTEGER ptsExpiry
        );

        [DllImport("secur32.DLL", CharSet = CharSet.Unicode)]
        public static extern IntPtr InitSecurityInterface();

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtQueryInformationProcess(
            IntPtr processHandle,
            UInt32 processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength,
            ref UInt32 returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [PreserveSig]
        public static extern uint GetModuleFileName(
            [In] IntPtr hModule,
            [Out] StringBuilder lpFilename,
            [In][MarshalAs(UnmanagedType.U4)]
            int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
           IntPtr hProcess,
           IntPtr lpBaseAddress,
           byte[] lpBuffer,
           Int32 nSize,
           out IntPtr lpNumberOfBytesRead);

        [DllImport("rpcrt4.dll")]
        public static extern int RpcServerUseProtseqEp(
            string Protseq,
            uint MaxCalls,
            string Endpoint,
            IntPtr SecurityDescriptor);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcServerRegisterAuthInfo", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int RpcServerRegisterAuthInfo(String ServerPrincName, uint AuthnSvc, IntPtr GetKeyFn, IntPtr Arg);

        [DllImport("ole32.dll")]
        public static extern int CoInitializeSecurity(
            IntPtr pSecDesc,
            int cAuthSvc,
            SOLE_AUTHENTICATION_SERVICE[] asAuthSvc,
            IntPtr pReserved1,
            AuthnLevel dwAuthnLevel,
            ImpLevel dwImpLevel,
            IntPtr pAuthList,
            EOLE_AUTHENTICATION_CAPABILITIES dwCapabilities,
            IntPtr pReserved3
        );

        //deleg
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate bool VERIFYSERVERCERT(
            IntPtr connection,
            IntPtr pServerCert);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int RPC_IF_CALLBACK_FN(IntPtr InterfaceUuid, IntPtr Context);

        public delegate SecStatusCode AcceptSecurityContextFunc(
            [In] SecHandle phCredential,
            [In] SecHandle phContext,
            [In] SecurityBufferDescriptor pInput,
            AcceptContextReqFlags fContextReq,
            SecDataRep TargetDataRep,
            [In, Out] SecHandle phNewContext,
            [In, Out] IntPtr pOutput,
            out AcceptContextRetFlags pfContextAttr,
            [Out] SECURITY_INTEGER ptsExpiry);

        //structs
        public enum EOLE_AUTHENTICATION_CAPABILITIES
        {
            EOAC_NONE = 0,
            EOAC_MUTUAL_AUTH = 0x1,
            EOAC_STATIC_CLOAKING = 0x20,
            EOAC_DYNAMIC_CLOAKING = 0x40,
            EOAC_ANY_AUTHORITY = 0x80,
            EOAC_MAKE_FULLSIC = 0x100,
            EOAC_DEFAULT = 0x800,
            EOAC_SECURE_REFS = 0x2,
            EOAC_ACCESS_CONTROL = 0x4,
            EOAC_APPID = 0x8,
            EOAC_DYNAMIC = 0x10,
            EOAC_REQUIRE_FULLSIC = 0x200,
            EOAC_AUTO_IMPERSONATE = 0x400,
            EOAC_NO_CUSTOM_MARSHAL = 0x2000,
            EOAC_DISABLE_AAA = 0x1000
        }

        public enum AuthnLevel
        {
            RPC_C_AUTHN_LEVEL_DEFAULT = 0,
            RPC_C_AUTHN_LEVEL_NONE = 1,
            RPC_C_AUTHN_LEVEL_CONNECT = 2,
            RPC_C_AUTHN_LEVEL_CALL = 3,
            RPC_C_AUTHN_LEVEL_PKT = 4,
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6
        }

        public enum ImpLevel
        {
            RPC_C_IMP_LEVEL_DEFAULT = 0,
            RPC_C_IMP_LEVEL_ANONYMOUS = 1,
            RPC_C_IMP_LEVEL_IDENTIFY = 2,
            RPC_C_IMP_LEVEL_IMPERSONATE = 3,
            RPC_C_IMP_LEVEL_DELEGATE = 4,
        }

        public struct SOLE_AUTHENTICATION_SERVICE
        {
            public int dwAuthnSvc;
            public int dwAuthzSvc;
            [MarshalAs(UnmanagedType.LPWStr)] public string pPrincipalName;
            public int hr;
        }

        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public int InheritedFromUniqueProcessId;

            public int Size => Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [Flags]
        public enum AcceptContextRetFlags
        {
            None = 0,
            Delegate = 0x00000001,
            MutualAuth = 0x00000002,
            ReplayDetect = 0x00000004,
            SequenceDetect = 0x00000008,
            Confidentiality = 0x00000010,
            UseSessionKey = 0x00000020,
            SessionTicket = 0x00000040,
            AllocatedMemory = 0x00000100,
            UsedDceStyle = 0x00000200,
            Datagram = 0x00000400,
            Connection = 0x00000800,
            CallLevel = 0x00002000,
            ThirdLegFailed = 0x00004000,
            ExtendedError = 0x00008000,
            Stream = 0x00010000,
            Integrity = 0x00020000,
            Licensing = 0x00040000,
            Identify = 0x00080000,
            NullSession = 0x00100000,
            AllowNonUserLogons = 0x00200000,
            AllowContextReplay = 0x00400000,
            FragmentOnly = 0x00800000,
            NoToken = 0x01000000,
            NoAdditionalToken = 0x02000000,
        }

        [Flags]
        public enum AcceptContextReqFlags
        {
            None = 0,
            Delegate = 0x00000001,
            MutualAuth = 0x00000002,
            ReplayDetect = 0x00000004,
            SequenceDetect = 0x00000008,
            Confidentiality = 0x00000010,
            UseSessionKey = 0x00000020,
            SessionTicket = 0x00000040,
            AllocateMemory = 0x00000100,
            UseDceStyle = 0x00000200,
            Datagram = 0x00000400,
            Connection = 0x00000800,
            CallLevel = 0x00001000,
            FragmentSupplied = 0x00002000,
            ExtendedError = 0x00008000,
            Stream = 0x00010000,
            Integrity = 0x00020000,
            Licensing = 0x00040000,
            Identify = 0x00080000,
            AllowNullSessions = 0x00100000,
            AllowNonUserLogons = 0x00200000,
            AllowContextReplay = 0x00400000,
            FragmentToFit = 0x00800000,
            NoToken = 0x01000000,
            ProxyBindings = 0x04000000,
            AllowMissingBindings = 0x10000000
        }

        public enum LdapModOperation
        {
            LDAP_MOD_ADD = 0x00,
            LDAP_MOD_DELETE = 0x01,
            LDAP_MOD_REPLACE = 0x02,
            LDAP_MOD_BVALUES = 0x80
        }

        public enum LdapSearchScope
        {
            LDAP_SCOPE_BASE = 0x0000,
            LDAP_SCOPE_BASEOBJECT = LDAP_SCOPE_BASE,
            LDAP_SCOPE_ONELEVEL = 0x0001,
            LDAP_SCOPE_ONE = LDAP_SCOPE_ONELEVEL,
            LDAP_SCOPE_SUBTREE = 0x0002,
            LDAP_SCOPE_SUB = LDAP_SCOPE_SUBTREE,
            LDAP_SCOPE_SUBORDINATE = 0x0003, /* OpenLDAP extension */
            LDAP_SCOPE_CHILDREN = LDAP_SCOPE_SUBORDINATE,
            LDAP_SCOPE_DEFAULT = -1 /* OpenLDAP extension */
        }

        public enum LdapResultType
        {
            LDAP_ERROR = -1,
            LDAP_TIMEOUT = 0,
            LDAP_RES_BIND = 0x61,
            LDAP_RES_SEARCH_ENTRY = 0x64,
            LDAP_RES_SEARCH_REFERENCE = 0x73,
            LDAP_RES_SEARCH_RESULT = 0x65,
            LDAP_RES_MODIFY = 0x67,
            LDAP_RES_ADD = 0x69,
            LDAP_RES_DELETE = 0x6b,
            LDAP_RES_MODDN = 0x6d,
            LDAP_RES_COMPARE = 0x6f,
            LDAP_RES_EXTENDED = 0x78,
            LDAP_RES_INTERMEDIATE = 0x79
        }

        public enum LdapStatus
        {
            LDAP_SUCCESS = 0,
            LDAP_OPERATIONS_ERROR = 1,

            //LDAP_PROTOCOL_ERROR = 2,
            LDAP_TIMELIMIT_EXCEEDED = 3,

            LDAP_SIZELIMIT_EXCEEDED = 4,

            //LDAP_COMPARE_FALSE = 5,
            //LDAP_COMPARE_TRUE = 6,
            LDAP_AUTH_METHOD_NOT_SUPPORTED = 7,

            //LDAP_STRONG_AUTH_REQUIRED = 8,
            //LDAP_REFERRAL = 9,
            //LDAP_ADMIN_LIMIT_EXCEEDED = 11,
            //LDAP_UNAVAILABLE_CRITICAL_EXTENSION = 12,
            //LDAP_CONFIDENTIALITY_REQUIRED = 13,
            LDAP_SASL_BIND_IN_PROGRESS = 14,

            LDAP_NO_SUCH_ATTRIBUTE = 16,
            LDAP_UNDEFINED_TYPE = 17,

            //LDAP_INAPPROPRIATE_MATCHING = 18,
            LDAP_CONSTRAINT_VIOLATION = 19,

            LDAP_TYPE_OR_VALUE_EXISTS = 20,
            LDAP_INVALID_SYNTAX = 21,

            LDAP_NO_SUCH_OBJECT = 32,

            //LDAP_ALIAS_PROBLEM = 33,
            LDAP_INVALID_DN_SYNTAX = 34,

            //LDAP_IS_LEAF = 35,
            //LDAP_ALIAS_DEREF_PROBLEM = 36,

            //LDAP_INAPPROPRIATE_AUTH = 48,
            LDAP_INVALID_CREDENTIALS = 49,

            LDAP_INSUFFICIENT_ACCESS = 50,
            LDAP_BUSY = 51,
            LDAP_UNAVAILABLE = 52,
            LDAP_UNWILLING_TO_PERFORM = 53,
            //LDAP_LOOP_DETECT = 54,

            //LDAP_NAMING_VIOLATION = 64,
            LDAP_OBJECT_CLASS_VIOLATION = 65,

            LDAP_NOT_ALLOWED_ON_NONLEAF = 66,

            //LDAP_NOT_ALLOWED_ON_RDN = 67,
            LDAP_ALREADY_EXISTS = 68,

            //LDAP_NO_OBJECT_CLASS_MODS = 69,
            //LDAP_RESULTS_TOO_LARGE = 70,
            //LDAP_AFFECTS_MULTIPLE_DSAS = 71,
            //LDAP_OTHER = 80,

            LDAP_SERVER_DOWN = -1,
            //LDAP_LOCAL_ERROR = -2,
            //LDAP_ENCODING_ERROR = -3,
            //LDAP_DECODING_ERROR = -4,
            //LDAP_TIMEOUT = -5,
            //LDAP_AUTH_UNKNOWN = -6,
            //LDAP_FILTER_ERROR = -7,
            //LDAP_USER_CANCELLED = -8,
            //LDAP_PARAM_ERROR = -9,
            //LDAP_NO_MEMORY = -10,
            //LDAP_CONNECT_ERROR = -11,
            //LDAP_NOT_SUPPORTED = -12,
            //LDAP_CONTROL_NOT_FOUND = -13,
            //LDAP_NO_RESULTS_RETURNED = -14,
            //LDAP_MORE_RESULTS_TO_RETURN = -15,

            //LDAP_CLIENT_LOOP = -16,
            //LDAP_REFERRAL_LIMIT_EXCEEDED = -17,
        }

        //https://github.com/go-win/go-windows/blob/3c4cf4813fb68a44704529efb5f5c78ecbb1b380/windows/win32/ldap/enums.go#L11

        [StructLayout(LayoutKind.Sequential)]
        public sealed class LDAPMod
        {
            /// <summary>
            /// Values that you want to add, delete, or replace.
            /// </summary>
            [StructLayout(LayoutKind.Explicit)]
            public struct mod_vals
            {
                /// <summary>
                /// Pointer to a NULL terminated array of string values for the attribute.
                /// </summary>
                [FieldOffset(0)] public IntPtr modv_strvals;

                /// <summary>
                /// Pointer to a NULL-terminated array of berval structures for the attribute.
                /// </summary>
                [FieldOffset(0)] public IntPtr modv_bvals;
            }

            /// <summary>
            /// The operation to be performed on the attribute and the type of data specified as the attribute values.
            /// </summary>
            public int mod_op;

            /// <summary>
            /// Pointer to the attribute type that you want to add, delete, or replace.
            /// </summary>
            public IntPtr mod_type;

            /// <summary>
            /// A NULL-terminated array of string values for the attribute.
            /// </summary>
            public mod_vals mod_vals_u;

            public IntPtr mod_next;
        }

        //#pragma warning disable 1591
        [StructLayout(LayoutKind.Sequential)]
        public class SecHandle
        {
            public IntPtr dwLower;
            public IntPtr dwUpper;
        }

        [Flags]
        public enum SecDataRep
        {
            /// <summary>
            /// Native representation.
            /// </summary>
            Native = 0x00000010,

            /// <summary>
            /// Network representation.
            /// </summary>
            Network = 0x00000000
        }

        [Flags]
        public enum SecStatusCode : uint
        {
            SUCCESS = 0,
            SEC_I_CONTINUE_NEEDED = 0x00090312,
            SEC_I_COMPLETE_NEEDED = 0x00090313,
            SEC_I_COMPLETE_AND_CONTINUE = 0x00090314,
            SEC_I_ASYNC_CALL_PENDING = 0x00090368,
            SEC_I_CONTEXT_EXPIRED = 0x00090317,
            SEC_I_CONTINUE_NEEDED_MESSAGE_OK = 0x00090366,
            SEC_I_GENERIC_EXTENSION_RECEIVED = 0x00090316,
            SEC_I_INCOMPLETE_CREDENTIALS = 0x00090320,
            SEC_I_LOCAL_LOGON = 0x00090315,
            SEC_I_MESSAGE_FRAGMENT = 0x00090364,
            SEC_I_NO_LSA_CONTEXT = 0x00090323,
            SEC_I_NO_RENEGOTIATION = 0x00090360,
            SEC_I_RENEGOTIATE = 0x00090321,
            SEC_I_SIGNATURE_NEEDED = 0x0009035C,
            SEC_E_ALGORITHM_MISMATCH = 0x80090331,
            SEC_E_APPLICATION_PROTOCOL_MISMATCH = 0x80090367,
            SEC_E_BAD_BINDINGS = 0x80090346,
            SEC_E_BAD_PKGID = 0x80090316,
            SEC_E_BUFFER_TOO_SMALL = 0x80090321,
            SEC_E_CANNOT_INSTALL = 0x80090307,
            SEC_E_CANNOT_PACK = 0x80090309,
            SEC_E_CERT_EXPIRED = 0x80090328,
            SEC_E_CERT_UNKNOWN = 0x80090327,
            SEC_E_CERT_WRONG_USAGE = 0x80090349,
            SEC_E_CONTEXT_EXPIRED = 0x80090317,
            SEC_E_CROSSREALM_DELEGATION_FAILURE = 0x80090357,
            SEC_E_CRYPTO_SYSTEM_INVALID = 0x80090337,
            SEC_E_DECRYPT_FAILURE = 0x80090330,
            SEC_E_DELEGATION_POLICY = 0x8009035E,
            SEC_E_DELEGATION_REQUIRED = 0x80090345,
            SEC_E_DOWNGRADE_DETECTED = 0x80090350,
            SEC_E_ENCRYPT_FAILURE = 0x80090329,
            SEC_E_EXT_BUFFER_TOO_SMALL = 0x8009036A,
            SEC_E_ILLEGAL_MESSAGE = 0x80090326,
            SEC_E_INCOMPLETE_CREDENTIALS = 0x80090320,
            SEC_E_INCOMPLETE_MESSAGE = 0x80090318,
            SEC_E_INSUFFICIENT_BUFFERS = 0x8009036B,
            SEC_E_INSUFFICIENT_MEMORY = 0x80090300,
            SEC_E_INTERNAL_ERROR = 0x80090304,
            SEC_E_INVALID_HANDLE = 0x80090301,
            SEC_E_INVALID_PARAMETER = 0x8009035D,
            SEC_E_INVALID_TOKEN = 0x80090308,
            SEC_E_INVALID_UPN_NAME = 0x80090369,
            SEC_E_ISSUING_CA_UNTRUSTED = 0x80090352,
            SEC_E_ISSUING_CA_UNTRUSTED_KDC = 0x80090359,
            SEC_E_KDC_CERT_EXPIRED = 0x8009035A,
            SEC_E_KDC_CERT_REVOKED = 0x8009035B,
            SEC_E_KDC_INVALID_REQUEST = 0x80090340,
            SEC_E_KDC_UNABLE_TO_REFER = 0x80090341,
            SEC_E_KDC_UNKNOWN_ETYPE = 0x80090342,
            SEC_E_LOGON_DENIED = 0x8009030C,
            SEC_E_MAX_REFERRALS_EXCEEDED = 0x80090338,
            SEC_E_MESSAGE_ALTERED = 0x8009030F,
            SEC_E_MULTIPLE_ACCOUNTS = 0x80090347,
            SEC_E_MUST_BE_KDC = 0x80090339,
            SEC_E_MUTUAL_AUTH_FAILED = 0x80090363,
            SEC_E_NOT_OWNER = 0x80090306,
            SEC_E_NO_AUTHENTICATING_AUTHORITY = 0x80090311,
            SEC_E_NO_CONTEXT = 0x80090361,
            SEC_E_NO_CREDENTIALS = 0x8009030E,
            SEC_E_NO_IMPERSONATION = 0x8009030B,
            SEC_E_NO_IP_ADDRESSES = 0x80090335,
            SEC_E_NO_KERB_KEY = 0x80090348,
            SEC_E_NO_PA_DATA = 0x8009033C,
            SEC_E_NO_S4U_PROT_SUPPORT = 0x80090356,
            SEC_E_NO_TGT_REPLY = 0x80090334,
            SEC_E_ONLY_HTTPS_ALLOWED = 0x80090365,
            SEC_E_OUT_OF_SEQUENCE = 0x80090310,
            SEC_E_PKINIT_CLIENT_FAILURE = 0x80090354,
            SEC_E_PKINIT_NAME_MISMATCH = 0x8009033D,
            SEC_E_PKU2U_CERT_FAILURE = 0x80090362,
            SEC_E_POLICY_NLTM_ONLY = 0x8009035F,
            SEC_E_QOP_NOT_SUPPORTED = 0x8009030A,
            SEC_E_REVOCATION_OFFLINE_C = 0x80090353,
            SEC_E_REVOCATION_OFFLINE_KDC = 0x80090358,
            SEC_E_SECPKG_NOT_FOUND = 0x80090305,
            SEC_E_SECURITY_QOS_FAILED = 0x80090332,
            SEC_E_SHUTDOWN_IN_PROGRESS = 0x8009033F,
            SEC_E_SMARTCARD_CERT_EXPIRED = 0x80090355,
            SEC_E_SMARTCARD_CERT_REVOKED = 0x80090351,
            SEC_E_SMARTCARD_LOGON_REQUIRED = 0x8009033E,
            SEC_E_STRONG_CRYPTO_NOT_SUPPORTED = 0x8009033A,
            SEC_E_TARGET_UNKNOWN = 0x80090303,
            SEC_E_TIME_SKEW = 0x80090324,
            SEC_E_TOO_MANY_PRINCIPALS = 0x8009033B,
            SEC_E_UNFINISHED_CONTEXT_DELETED = 0x80090333,
            SEC_E_UNKNOWN_CREDENTIALS = 0x8009030D,
            SEC_E_UNSUPPORTED_FUNCTION = 0x80090302,
            SEC_E_UNSUPPORTED_PREAUTH = 0x80090343,
            SEC_E_UNTRUSTED_ROOT = 0x80090325,
            SEC_E_WRONG_CREDENTIAL_HANDLE = 0x80090336,
            SEC_E_WRONG_PRINCIPAL = 0x80090322,
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct SecurityFunctionTable
        {
            /// <summary>Version number of the table.</summary>
            public uint dwVersion;

            /// <summary>Pointer to the EnumerateSecurityPackages function.</summary>
            public IntPtr EnumerateSecurityPackages;

            /// <summary>Pointer to the QueryCredentialsAttributes function.</summary>
            public IntPtr QueryCredentialsAttributes;

            /// <summary>Pointer to the AcquireCredentialsHandle function.</summary>
            public IntPtr AcquireCredentialsHandle;

            /// <summary>Pointer to the FreeCredentialsHandle function.</summary>
            public IntPtr FreeCredentialHandl;

            /// <summary>Reserved for future use.</summary>
            public IntPtr Reserved1;

            /// <summary>Pointer to the InitializeSecurityContext (General) function.</summary>
            public IntPtr InitializeSecurityContext;

            /// <summary>Pointer to the AcceptSecurityContext (General) function.</summary>
            public IntPtr AcceptSecurityContex;

            /// <summary>Pointer to the CompleteAuthToken function.</summary>
            public IntPtr CompleteAuthToke;

            /// <summary>Pointer to the DeleteSecurityContext function.</summary>
            public IntPtr DeleteSecurityContex;

            /// <summary>Pointer to the ApplyControlToken function.</summary>
            public IntPtr ApplyControlToke;

            /// <summary>Pointer to the QueryContextAttributes (General) function.</summary>
            public IntPtr QueryContextAttributes;

            /// <summary>Pointer to the ImpersonateSecurityContext function.</summary>
            public IntPtr ImpersonateSecurityContex;

            /// <summary>Pointer to the RevertSecurityContext function.</summary>
            public IntPtr RevertSecurityContex;

            /// <summary>Pointer to the MakeSignature function.</summary>
            public IntPtr MakeSignatur;

            /// <summary>Pointer to the VerifySignature function.</summary>
            public IntPtr VerifySignatur;

            /// <summary>Pointer to the FreeContextBuffer function.</summary>
            public IntPtr FreeContextBuffe;

            /// <summary>Pointer to the QuerySecurityPackageInfo function.</summary>
            public IntPtr QuerySecurityPackageInfo;

            /// <summary>Reserved for future use.</summary>
            public IntPtr Reserved2;

            /// <summary>Reserved for future use.</summary>
            public IntPtr Reserved3;

            /// <summary>Pointer to the ExportSecurityContext function.</summary>
            public IntPtr ExportSecurityContex;

            /// <summary>Pointer to the ImportSecurityContext function.</summary>
            public IntPtr ImportSecurityContext;

            /// <summary>Pointer to the AddCredential function.</summary>
            public IntPtr AddCredentials;

            /// <summary>Reserved for future use.</summary>
            public IntPtr Reserved4;

            /// <summary>Pointer to the QuerySecurityContextToken function.</summary>
            public IntPtr QuerySecurityContextToke;

            /// <summary>Pointer to the EncryptMessage (General) function.</summary>
            public IntPtr EncryptMessag;

            /// <summary>Pointer to the DecryptMessage (General) function.</summary>
            public IntPtr DecryptMessag;

            /// <summary>Pointer to the SetContextAttributes function.</summary>
            public IntPtr SetContextAttributes;

            /// <summary>Pointer to the SetCredentialsAttributes function.</summary>
            public IntPtr SetCredentialsAttributes;

            /// <summary>Pointer to the ChangeAccountPassword function.</summary>
            public IntPtr ChangeAccountPassword;

            /// <summary>Pointer to the AddCredential function.</summary>
            public IntPtr Reserved5;

            /// <summary>Pointer to the QueryContextAttributesEx function.</summary>
            public IntPtr QueryContextAttributesEx;

            /// <summary>Pointer to the QueryCredentialsAttributesEx function.</summary>
            public IntPtr QueryCredentialsAttributesEx;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_HANDLE
        {
            public IntPtr LowPart;
            public IntPtr HighPart;

            public SECURITY_HANDLE(int dummy)
            {
                LowPart = HighPart = IntPtr.Zero;
            }
        };

        [Flags]
        public enum SecBufferType
        {
            SECBUFFER_VERSION = 0,
            SECBUFFER_EMPTY = 0,
            SECBUFFER_DATA = 1,
            SECBUFFER_TOKEN = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SecBuffer : IDisposable
        {
            public int cbBuffer;
            public int bufferType;
            public IntPtr pvBuffer;

            public SecBuffer(int bufferSize)
            {
                cbBuffer = bufferSize;
                bufferType = (int)SecBufferType.SECBUFFER_TOKEN;
                if (bufferSize > 0)
                {
                    pvBuffer = Marshal.AllocHGlobal(bufferSize);
                }
                else
                {
                    pvBuffer = IntPtr.Zero;
                }
            }

            public SecBuffer(byte[] secBufferBytes)
            {
                cbBuffer = secBufferBytes.Length;
                bufferType = (int)SecBufferType.SECBUFFER_TOKEN;
                pvBuffer = Marshal.AllocHGlobal(cbBuffer);
                Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
            }

            public SecBuffer(byte[] secBufferBytes, SecBufferType bufferType)
            {
                cbBuffer = secBufferBytes.Length;
                this.bufferType = (int)bufferType;
                pvBuffer = Marshal.AllocHGlobal(cbBuffer);
                Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
            }

            public void Dispose()
            {
                if (pvBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pvBuffer);
                    pvBuffer = IntPtr.Zero;
                }
            }

            public byte[] GetBytes()
            {
                byte[] buffer = null;
                if (cbBuffer > 0)
                {
                    buffer = new byte[cbBuffer];
                    Marshal.Copy(pvBuffer, buffer, 0, cbBuffer);
                }
                return buffer;
            }

            public byte[] GetBytes(int bytes)
            {
                byte[] buffer = null;
                if (cbBuffer > 0)
                {
                    buffer = new byte[cbBuffer + bytes];
                    Marshal.Copy(pvBuffer, buffer, 0, cbBuffer + bytes);
                }
                return buffer;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SecBufferDesc : IDisposable
        {
            public int ulVersion;
            public int cBuffers;
            public IntPtr pBuffers; //Point to SecBuffer

            public SecBufferDesc(int bufferSize)
            {
                ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
                cBuffers = 1;
                SecBuffer secBuffer = new SecBuffer(bufferSize);
                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(secBuffer));
                Marshal.StructureToPtr(secBuffer, pBuffers, false);
            }

            public SecBufferDesc(byte[] secBufferBytes)
            {
                ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
                cBuffers = 1;
                SecBuffer secBuffer = new SecBuffer(secBufferBytes);
                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(secBuffer));
                Marshal.StructureToPtr(secBuffer, pBuffers, false);
            }

            public void Dispose()
            {
                if (pBuffers != IntPtr.Zero)
                {
                    SecBuffer secBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                    secBuffer.Dispose();
                    Marshal.FreeHGlobal(pBuffers);
                    pBuffers = IntPtr.Zero;
                }
            }

            public SecBuffer GetSecBuffer()
            {
                if (pBuffers == IntPtr.Zero)
                    throw new ObjectDisposedException("SecBufferDesc");
                SecBuffer secBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                return secBuffer;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_INTEGER
        {
            public uint LowPart;
            public int HighPart;

            public SECURITY_INTEGER(int dummy)
            {
                LowPart = 0;
                HighPart = 0;
            }
        };
    }
}