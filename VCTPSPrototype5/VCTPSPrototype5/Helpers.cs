using Google.Protobuf;
using Okapi.Transport;
using Okapi.Transport.V1;
using Pbmse.V1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Okapi.Security.V1;
using Okapi.Security;

namespace VCTPSPrototype5
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

            return template;
        }

        // https://docs.microsoft.com/en-us/dotnet/api/system.convert.tobase64string?view=net-5.0#System_Convert_ToBase64String_System_Byte___
        public static string ToBase64String(string s)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(s);
            string s64 = Convert.ToBase64String(bytes);
            return s64;
        }
        public static string ToBase64String(byte[] bytes)
        {
            string s64 = Convert.ToBase64String(bytes);
            return s64;
        }
        public static byte[] FromBase64String(string s)
        {
            byte[] bytes = Convert.FromBase64String(s);
            return bytes;
        }

        public static int HttpMessagesSent = 0;
        public static int DIDCOMMMessagesSent = 0;
        static readonly HttpClient httpClient = new HttpClient(); // https://www.thecodebuzz.com/using-httpclient-best-practices-and-anti-patterns/

        private static string SendHttpMessage(string url, string jsonRequest)
        {
            string jsonResponse = "{ }";

            HttpMessagesSent++;
            Console.WriteLine("SendHTTPCOMMMessage: " + Helpers.DIDCOMMMessagesSent.ToString() + " DIDCOMM sent. " + Helpers.HttpMessagesSent.ToString() + " HTTP sent. " + Program.MessagesReceived.ToString() + " HTTP rcvd.");

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

        public static string SendDIDCOMMMessage(string DIDCOMMEndpointUrl, string from, string to, CoreMessage core)
        {
            string jsonResponse = "{ }";

            Console.WriteLine("SendDIDCOMMMessage: " + Helpers.DIDCOMMMessagesSent.ToString() + " DIDCOMM sent. " + Helpers.HttpMessagesSent.ToString() + " HTTP sent. " + Program.MessagesReceived.ToString() + " HTTP rcvd.");

            Console.WriteLine(">>Sending to: " + Program.KeyVault[to].Name + "\t" + to); ;
            var encryptedPackage = DIDComm.Pack(new PackRequest { Plaintext = core.ToByteString(), 
                                                                    SenderKey = Program.KeyVault[from].MsgSk, 
                                                                    ReceiverKey = Program.KeyVault[to].MsgPk, 
                                                                    Mode = EncryptionMode.Direct });
            var emessage = encryptedPackage.Message;
            VCTPSEncryptedMessage em = new VCTPSEncryptedMessage(emessage.Iv.ToBase64(), emessage.Ciphertext.ToBase64(), emessage.Tag.ToBase64(),
                recipients64: new List<string>() { emessage.Recipients[0].ToByteString().ToBase64() });
            VCTPSMessage msg = new VCTPSMessage(em);
            var emJson = msg.ToString();
            var task = Task.Run(() => Helpers.SendHttpMessage(DIDCOMMEndpointUrl, emJson));
            DIDCOMMMessagesSent++;


            return jsonResponse;
        }
    }

    static public class SHA256Helpers
    {
        static private SHA256 HashProvider = SHA256.Create();

        // https://docs.microsoft.com/en-us/dotnet/standard/security/ensuring-data-integrity-with-hash-codes
        public static byte[] ComputeHash(byte[] bytes)
        {
            byte[] hash;

            hash = HashProvider.ComputeHash(bytes);

            return hash;
        }

        public static string ComputeHash(string plaintext)
        {
            string hash64;
            byte[] hash;

            byte[] bytes = Encoding.UTF8.GetBytes(plaintext);
            hash = HashProvider.ComputeHash(bytes);
            hash64 = Helpers.ToBase64String(hash);

            return hash64;
        }

        public static byte[] ComputeFileHash(string inFile)
        {
            byte[] hashedValue;

            byte[] fileBytes = File.ReadAllBytes(inFile);

            hashedValue = ComputeHash(fileBytes);

            return hashedValue;
        }
    }

    public static class ProofHelpers
    {
        public static string ComputeProof(string hash64, ByteString proofSk, string nonce64)
        {
            ByteString data = ByteString.FromBase64(hash64);
            var token = Oberon.CreateToken(new CreateOberonTokenRequest
            {
                Data = data,
                Sk = proofSk
            });

            ByteString nonce = ByteString.FromBase64(nonce64);
            CreateOberonProofResponse proof = Oberon.CreateProof(new CreateOberonProofRequest
            {
                Data = data,
                Nonce = nonce,
                Token = token.Token
            });

            string proof64 = proof.Proof.ToBase64();
            return proof64;
        }
    }
}
