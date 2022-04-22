using Google.Protobuf;
using Okapi.Transport;
using Okapi.Transport.V1;
using Pbmse.V1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VCTPSPrototype4
{
    public static class Helpers
    {
        static System.Reflection.Assembly assembly = typeof(Program).Assembly;

        public static string GetTemplate(string resname)
        {
            var streams = assembly.GetManifestResourceNames();
            var nfeJsonEnvelopeStream = assembly.GetManifestResourceStream(resname);
            if (nfeJsonEnvelopeStream == null) return "";
            byte[] res = new byte[nfeJsonEnvelopeStream.Length];
            int nBytes = nfeJsonEnvelopeStream.Read(res);
            string template = Encoding.UTF8.GetString(res);

            if (String.IsNullOrEmpty(template)) throw new NullReferenceException("GetTemplate");

            return template;
        }
    }

    public static class DIDCOMMHelpers
    { 
        public static int HttpMessagesSent = 0;
        public static int DIDCOMMMessagesSent = 0;
        static readonly HttpClient httpClient = new HttpClient(); 
        // https://www.thecodebuzz.com/using-httpclient-best-practices-and-anti-patterns/

        private static string SendHttpMessage(string url, string jsonRequest)
        {
            string jsonResponse = "{ }";

            HttpMessagesSent++;
            Console.WriteLine("SendHTTPCOMMMessage: " 
                + DIDCOMMHelpers.DIDCOMMMessagesSent.ToString() + " DIDCOMM sent. " 
                + DIDCOMMHelpers.HttpMessagesSent.ToString() + " HTTP sent. " 
                + Program.MessagesReceived.ToString() + " HTTP rcvd.");

            Console.WriteLine(">>>Agent Url:" + url);
            using (var requestMessage = new HttpRequestMessage(new HttpMethod("POST"), url))
            {
                requestMessage.Headers.TryAddWithoutValidation("Accept", "application/json");
                Console.WriteLine(">>>Request:" + jsonRequest);
                requestMessage.Content = new StringContent(jsonRequest);
                var task = httpClient.SendAsync(requestMessage);
                task.Wait();
                //var result = task.Result;
                //jsonResponse = result.Content.ReadAsStringAsync().Result;
                //Console.WriteLine(">>>Response:" + url);
            }

            return jsonResponse;
        }

        public static void SendDIDCOMMMessage(string DIDCOMMEndpointUrl, CoreMessage core)
        {
            foreach (var to in core.To.ToList())
            {
                DIDCOMMHelpers.SendDIDCOMMMessage(DIDCOMMEndpointUrl, core.From, to, core);
            }
        }

        public static string SendDIDCOMMMessage(string DIDCOMMEndpointUrl, string from, string to, CoreMessage core)
        {
            string jsonResponse = "{ }";

            Console.WriteLine("SendDIDCOMMMessage: " 
                + DIDCOMMHelpers.DIDCOMMMessagesSent.ToString() + " DIDCOMM sent. " 
                + DIDCOMMHelpers.HttpMessagesSent.ToString() + " HTTP sent. " 
                + Program.MessagesReceived.ToString() + " HTTP rcvd.");

            Console.WriteLine(">>Sending to: " + Program.KeyVault[to].Name + "\t" + to); ;
            var encryptedPackage = DIDComm.Pack(new PackRequest { Plaintext = core.ToByteString(), 
                                                                    SenderKey = Program.KeyVault[from].MsgSk, 
                                                                    ReceiverKey = Program.KeyVault[to].MsgPk, 
                                                                    Mode = EncryptionMode.Direct });
            var emessage = encryptedPackage.Message;
            DIDCOMMEncryptedMessage em = new DIDCOMMEncryptedMessage(emessage.Iv.ToBase64(), emessage.Ciphertext.ToBase64(), emessage.Tag.ToBase64(),
                recipients64: new List<string>() { emessage.Recipients[0].ToByteString().ToBase64() });
            DIDCOMMMessage msg = new DIDCOMMMessage(em);
            var emJson = msg.ToString();
            // Perform async HTTP POST
            var task = Task.Run(() => DIDCOMMHelpers.SendHttpMessage(DIDCOMMEndpointUrl, emJson));
            DIDCOMMMessagesSent++;

            return jsonResponse;
        }
    }
}
