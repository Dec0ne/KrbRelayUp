using System;
using System.Runtime.InteropServices;

namespace KrbRelayUp.Relay
{
    /// <summary>
    /// Taken and stripped from https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/Interop.cs
    /// </summary>
    public class Interop
    {
        // constants

        // Enums
        // from https://tools.ietf.org/html/rfc3961
        public enum KERB_ETYPE : UInt32
        {
            des_cbc_crc = 1,
            des_cbc_md4 = 2,
            des_cbc_md5 = 3,
            des3_cbc_md5 = 5,
            des3_cbc_sha1 = 7,
            dsaWithSHA1_CmsOID = 9,
            md5WithRSAEncryption_CmsOID = 10,
            sha1WithRSAEncryption_CmsOID = 11,
            rc2CBC_EnvOID = 12,
            rsaEncryption_EnvOID = 13,
            rsaES_OAEP_ENV_OID = 14,
            des_ede3_cbc_Env_OID = 15,
            des3_cbc_sha1_kd = 16,
            aes128_cts_hmac_sha1 = 17,
            aes256_cts_hmac_sha1 = 18,
            rc4_hmac = 23,
            rc4_hmac_exp = 24,
            subkey_keymaterial = 65
        }

        // structs
        // From Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L1773-L1794
        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_ECRYPT
        {
            private int Type0;
            public int BlockSize;
            private int Type1;
            public int KeySize;
            public int Size;
            private int unk2;
            private int unk3;
            public IntPtr AlgName;
            public IntPtr Initialize;
            public IntPtr Encrypt;
            public IntPtr Decrypt;
            public IntPtr Finish;
            public IntPtr HashPassword;
            private IntPtr RandomKey;
            private IntPtr Control;
            private IntPtr unk0_null;
            private IntPtr unk1_null;
            private IntPtr unk2_null;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        // functions
        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        [DllImport("cryptdll.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int CDLocateCSystem(KERB_ETYPE type, out IntPtr pCheckSum);

        public delegate int KERB_ECRYPT_HashPassword(UNICODE_STRING Password, UNICODE_STRING Salt, int count, byte[] output);
    }
}