using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


// Based on https://github.com/bats3c/ADCSPwn/blob/master/ADCSPwn/PKCS12%20.cs
namespace KrbRelayUp.Relay.Misc
{
    class PasswordStore : IPasswordFinder
    {
        private char[] password;

        public PasswordStore(
                    char[] password)
        {
            this.password = password;
        }

        public char[] GetPassword()
        {
            return (char[])password.Clone();
        }

    }
    public class PKCS12
    {
        //Based on https://stackoverflow.com/questions/3097642/convert-a-pem-certificate-to-pfx-programmatically-using-openssl
        public static string ConvertToPKCS12(string plainCert)
        {
            using (TextReader sr = new StringReader(plainCert))
            {
                IPasswordFinder passwordFinder = new PasswordStore("".ToCharArray());
                PemReader pemReader = new PemReader(sr, passwordFinder);


                Pkcs12Store store = new Pkcs12StoreBuilder().Build();
                X509CertificateEntry[] chain = new X509CertificateEntry[1];
                AsymmetricCipherKeyPair privKey = null;

                object o;
                while ((o = pemReader.ReadObject()) != null)
                {
                    if (o is X509Certificate)
                    {
                        chain[0] = new X509CertificateEntry((X509Certificate)o);
                    }
                    else if (o is AsymmetricCipherKeyPair)
                    {
                        privKey = (AsymmetricCipherKeyPair)o;
                    }
                }

                store.SetKeyEntry("", new AsymmetricKeyEntry(privKey.Private), chain);
                var p12file = new MemoryStream();
                store.Save(p12file, "".ToCharArray(), new SecureRandom());
                p12file.Close();

                return Convert.ToBase64String(p12file.ToArray());
            }
        }
    }
}
