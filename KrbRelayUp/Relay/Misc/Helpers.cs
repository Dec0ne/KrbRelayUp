using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace KrbRelayUp.Relay
{
    internal class Helpers
    {


        //https://github.com/rvazarkar/GMSAPasswordReader
        public static string KerberosPasswordHash(Interop.KERB_ETYPE etype, string password, string salt = "", int count = 4096)
        {
            // use the internal KERB_ECRYPT HashPassword() function to calculate a password hash of a given etype
            // adapted from @gentilkiwi's Mimikatz "kerberos::hash" implementation

            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;

            // locate the crypto system for the hash type we want
            int status = Interop.CDLocateCSystem(etype, out pCSystemPtr);

            pCSystem = (Interop.KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0)
                throw new Win32Exception(status, "Error on CDLocateCSystem");

            // get the delegate for the password hash function
            Interop.KERB_ECRYPT_HashPassword pCSystemHashPassword = (Interop.KERB_ECRYPT_HashPassword)Marshal.GetDelegateForFunctionPointer(pCSystem.HashPassword, typeof(Interop.KERB_ECRYPT_HashPassword));
            Interop.UNICODE_STRING passwordUnicode = new Interop.UNICODE_STRING(password);
            Interop.UNICODE_STRING saltUnicode = new Interop.UNICODE_STRING(salt);

            byte[] output = new byte[pCSystem.KeySize];

            int success = pCSystemHashPassword(passwordUnicode, saltUnicode, count, output);

            if (status != 0)
                throw new Win32Exception(status);

            return BitConverter.ToString(output).Replace("-", "");
        }

        public static byte[] unhexlify(string hexvalue)
        {
            if (hexvalue.Length % 2 != 0)
                hexvalue = "0" + hexvalue;
            int len = hexvalue.Length / 2;
            byte[] bytes = new byte[len];
            for (int i = 0; i < len; i++)
            {
                string byteString = hexvalue.Substring(2 * i, 2);
                bytes[i] = Convert.ToByte(byteString, 16);
            }
            return bytes;
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static byte[] StringToByteArray(string s)
        {
            return Enumerable.Range(0, s.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(s.Substring(x, 2), 16))
                .ToArray();
        }

        public static void PrintProperties(object myObj, string header = "", int offset = 0)
        {
            string trail = String.Concat(Enumerable.Repeat(" ", offset));

            if (!string.IsNullOrEmpty(header))
                Console.WriteLine(header);

            foreach (var prop in myObj.GetType().GetProperties())
            {
                try
                {
                    if (!string.IsNullOrEmpty((string)(prop.GetValue(myObj, null))))
                        Console.WriteLine(trail + prop.Name + ": " + prop.GetValue(myObj, null));
                }
                catch (Exception e)
                {
                    Console.WriteLine(trail + prop.Name + ": " + prop.GetValue(myObj, null));
                }
            }

            foreach (var field in myObj.GetType().GetFields())
            {
                try
                {
                    if (!string.IsNullOrEmpty((string)field.GetValue(myObj)))
                        Console.WriteLine(trail + field.Name + ": " + field.GetValue(myObj));
                }
                catch (Exception e)
                {
                    Console.WriteLine(trail + field.Name + ": " + field.GetValue(myObj));
                }
            }
        }

        public static T ReadStruct<T>(byte[] array) where T : struct
        {
            var handle = GCHandle.Alloc(array, GCHandleType.Pinned);
            var mystruct = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return mystruct;
        }

        public static int FieldOffset<T>(string fieldName)
        {
            return Marshal.OffsetOf(typeof(T), fieldName).ToInt32();
        }

        public static int StructFieldOffset(Type s, string field)
        {
            var ex = typeof(Program);
            var mi = ex.GetMethod("FieldOffset");
            var miConstructed = mi.MakeGenericMethod(s);
            object[] args = { field };
            return (int)miConstructed.Invoke(null, args);
        }

        private static string GenRandomName()
        {
            Random r = new Random();
            StringBuilder builder = new StringBuilder();

            for (int i = 0; i < 8; i++)
            {
                int c = r.Next(26);
                builder.Append((char)('A' + c));
            }

            return builder.ToString();
        }

        public static byte[] EncodeLength(int length)

        {
            if (length < 0x80)

                return new[] { (byte)length };

            if (length < 0x100)

                return new byte[] { 0x81, (byte)length };

            if (length < 0x10000)

                return new byte[] { 0x82, (byte)(length >> 8),

                            (byte)(length & 0xFF) };

            throw new ArgumentException("Invalid length", nameof(length));
        }

        public static byte[] ConvertApReq(byte[] token)
        {
            if (token.Length == 0 || token[0] != 0x6E) //return if packet is not kerberos
                return token;

            MemoryStream stm = new MemoryStream();

            BinaryWriter writer = new BinaryWriter(stm);

            //write KRB5_OID + KRB5_tok_ID
            byte[] header = new byte[] { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01, 0x00 };

            writer.Write((byte)0x60);

            writer.Write(EncodeLength(header.Length + token.Length));

            writer.Write(header);

            writer.Write(token);

            return stm.ToArray();
        }

        public static List<int> SearchBytePattern(byte[] pattern, byte[] bytes)
        {
            List<int> positions = new List<int>();
            int patternLength = pattern.Length;
            int totalLength = bytes.Length;
            byte firstMatchByte = pattern[0];
            for (int i = 0; i < totalLength; i++)
            {
                if (firstMatchByte == bytes[i] && totalLength - i >= patternLength)
                {
                    byte[] match = new byte[patternLength];
                    Array.Copy(bytes, i, match, 0, patternLength);
                    if (match.SequenceEqual<byte>(pattern))
                    {
                        positions.Add(i);
                        i += patternLength - 1;
                    }
                }
            }
            return positions;
        }

        public static byte[] Combine(params byte[][] arrays)
        {
            byte[] ret = new byte[arrays.Sum(x => x.Length)];
            int offset = 0;
            foreach (byte[] data in arrays)
            {
                Buffer.BlockCopy(data, 0, ret, offset, data.Length);
                offset += data.Length;
            }
            return ret;
        }

        public static int PatternAt(byte[] src, byte[] pattern, bool firstMatch = false)
        {
            int maxFirstCharSlot = src.Length - pattern.Length + 1;
            for (int i = 0; i < maxFirstCharSlot; i++)
            {
                if (src[i] != pattern[0]) // compare only first byte
                    continue;
                if (firstMatch == true)
                    return i;
                // found a match on first byte, now try to match rest of the pattern
                for (int j = pattern.Length - 1; j >= 1; j--)
                {
                    if (src[i + j] != pattern[j]) break;
                    if (j == 1) return i;
                }
            }
            return -1;
        }

        public static byte[] ConvertHexStringToByteArray(string hexString)
        {
            if (hexString.Length % 2 != 0)
            {
                throw new ArgumentException(String.Format(CultureInfo.InvariantCulture, "The binary key cannot have an odd number of digits: {0}", hexString));
            }

            byte[] data = new byte[hexString.Length / 2];
            for (int index = 0; index < data.Length; index++)
            {
                string byteValue = hexString.Substring(index * 2, 2);
                data[index] = byte.Parse(byteValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            return data;
        }

        //ldap


        internal static IEnumerable<IntPtr> GetPointerArray(IntPtr array)
        {
            if (array != IntPtr.Zero)
            {
                var count = 0;
                var tempPtr = Marshal.ReadIntPtr(array, count * IntPtr.Size);
                while (tempPtr != IntPtr.Zero)
                {
                    yield return tempPtr;
                    count++;
                    tempPtr = Marshal.ReadIntPtr(array, count * IntPtr.Size);
                }
            }
        }

        internal static IntPtr AllocHGlobalIntPtrArray(int size)
        {
            checked
            {
                var intPtrArray = Marshal.AllocHGlobal(IntPtr.Size * size);
                for (var i = 0; i < size; i++)
                {
                    Marshal.WriteIntPtr(intPtrArray, IntPtr.Size * i, IntPtr.Zero);
                }

                return intPtrArray;
            }
        }

        internal static void StructureArrayToPtr<T>(IEnumerable<T> array, IntPtr ptr, bool endNull = false)
        {
            var ptrArray = array.Select(structure =>
            {
                var structPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T)));
                Marshal.StructureToPtr(structure, structPtr, false);
                return structPtr;
            }).ToList();
            if (endNull)
            {
                ptrArray.Add(IntPtr.Zero);
            }

            Marshal.Copy(ptrArray.ToArray(), 0, ptr, ptrArray.Count);
        }

        internal static void ByteArraysToBerValueArray(byte[][] sourceData, IntPtr ptr)
        {
            for (var i = 0; i < sourceData.Length; i++)
            {
                var berPtr = ByteArrayToBerValue(sourceData[i]);
                Marshal.WriteIntPtr(ptr, i * IntPtr.Size, berPtr);
            }

            Marshal.WriteIntPtr(ptr, sourceData.Length * IntPtr.Size, IntPtr.Zero);
        }

        internal static IntPtr ByteArrayToBerValue(byte[] bytes)
        {
            var berPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Natives.berval)));
            var valPtr = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, valPtr, bytes.Length);
            Marshal.StructureToPtr(new Natives.berval
            {
                bv_val = valPtr,
                bv_len = bytes.Length
            }, berPtr, true);
            return berPtr;
        }

        internal static void BerValFree(IntPtr berval)
        {
            if (berval != IntPtr.Zero)
            {
                var b = (Natives.berval)Marshal.PtrToStructure(berval, typeof(Natives.berval));
                Marshal.FreeHGlobal(b.bv_val);
                Marshal.FreeHGlobal(berval);
            }
        }

        internal static void BerValuesFree(IntPtr array)
        {
            foreach (var ptr in GetPointerArray(array))
            {
                BerValFree(ptr);
            }
        }

        public static List<byte[]> BerValArrayToByteArrays(IntPtr ptr)
        {
            var result = new List<byte[]>();
            foreach (var tempPtr in GetPointerArray(ptr))
            {
                var bervalue = new Natives.berval();
                Marshal.PtrToStructure(tempPtr, bervalue);
                if (bervalue.bv_len > 0 && bervalue.bv_val != IntPtr.Zero)
                {
                    var byteArray = new byte[bervalue.bv_len];
                    Marshal.Copy(bervalue.bv_val, byteArray, 0, bervalue.bv_len);
                    result.Add(byteArray);
                }
            }

            return result;
        }

        public static uint TrustAllCertificates(IntPtr ld)
        {
            return Natives.ldap_set_option(ld, 0x81, //LDAP_OPT_SERVER_CERTIFICATE
                Marshal.GetFunctionPointerForDelegate<Natives.VERIFYSERVERCERT>((connection, serverCert) => true));
        }
    }
}