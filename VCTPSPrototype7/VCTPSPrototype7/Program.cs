using Okapi.Transport;
using Okapi.Transport.V1;
using System;
using System.Text;
using Google.Protobuf;
using Okapi.Keys.V1;
using Pbmse.V1;
using System.Diagnostics;
using System.Text.Json;
using Okapi.Examples.V1;
using System.Collections.Concurrent;
using Okapi.Keys;
using VCTPS.Common;
using System.Reflection;
using VCTPS.Protocol;
using VCTPS.CredentialWallet;

namespace VCTPSPrototype6
{
    class DIDCOMMAgentImplementation : DIDCOMMAgentBase
    {
        public override void DIDCOMMEndpointHandler(DIDCOMMMessage request, out DIDCOMMResponse response)
        {
            DIDCOMMEncryptedMessage encryptedMessage = request.encryptedMessage;

            EncryptedMessage emessage = new EncryptedMessage();
            emessage.Iv = ByteString.FromBase64(encryptedMessage.lv64);
            emessage.Ciphertext = ByteString.FromBase64(encryptedMessage.ciphertext64);
            emessage.Tag = ByteString.FromBase64(encryptedMessage.tag64);
            EncryptionRecipient r = new EncryptionRecipient();
            r.MergeFrom(ByteString.FromBase64(encryptedMessage.recipients64[0]));
            emessage.Recipients.Add(r);

            string kid = r.Header.KeyId;
            string skid = r.Header.SenderKeyId;
            Console.WriteLine("DIDCOMMEndpointHandler: " + skid + " to\r\n" + kid);

            if (!Program.Queues.ContainsKey(kid)) Program.Queues.Add(kid, new ConcurrentQueue<EncryptedMessage>());
            Program.Queues[kid].Enqueue(emessage);

            response.rc = (int)Trinity.TrinityErrorCode.E_SUCCESS;

            Program.MessagesReceived++;
            Console.WriteLine("DIDCOMMEndpointHandler: " + DIDCOMMHelpers.DIDCOMMMessagesSent.ToString() + " DIDCOMM sent. " + DIDCOMMHelpers.HttpMessagesSent.ToString() + " HTTP sent. " + Program.MessagesReceived.ToString() + " HTTP rcvd.");
        }
    }

    public class Program
    {
        public static Dictionary<string, ConcurrentQueue<EncryptedMessage>> Queues = new Dictionary<string, ConcurrentQueue<EncryptedMessage>>();
        public static bool Processing = true;
        public const string DIDCOMMEndpointUrl = "http://localhost:8081/DIDCOMMEndpoint/";
        public static string vcJson;
        public static string vcaJson;
        public static string vcaackJson;
        public static int MessagesReceived = 0;

        static void Main(string[] args)
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            vcJson = Helpers.GetTemplate(assembly, "VCTPSPrototype6.vc2.json");
            vcaJson = Helpers.GetTemplate(assembly, "VCTPSPrototype6.vca2.json");
            vcaackJson = Helpers.GetTemplate(assembly, "VCTPSPrototype6.vcaack2.json");

            WalletHelpers.InitializeItems();
            WalletHelpers.InitializeParties();
            WalletHelpers.InitializeBusinessDocuments();

            string grantedkey = KeyVault.FindKey("Delta");
            string vcakid = DIDKey.Generate(new GenerateKeyRequest { KeyType = KeyType.X25519 }).Key[0].Kid;
            List<string> rights = new List<string>() { "read" };
            List<string> restrictions = new List<string>() { "forward" };
            List<string> processing = new List<string>() { "approve", "reject" };
            VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential(grantedkey, vcakid,
                rights, restrictions, processing, KeyVault.Find("Charlie").ProofKey.Sk, Helpers.ToBase64String("1234"));
            string sealedEnvelopeJson = vca.ToString();
            Console.WriteLine("sealedEnvelopeJson:\r\n" + sealedEnvelopeJson);

            Trinity.TrinityConfig.HttpPort = 8081;
            DIDCOMMAgentImplementation vctpAgent = new DIDCOMMAgentImplementation();
            vctpAgent.Start();
            Console.WriteLine("DIDCOMM Agent started...");

            var notify = VCTPSMessageFactory.NewNotifyMsg(KeyVault.FindKey("Charlie"), new string[] { KeyVault.FindKey("Delta"), KeyVault.FindKey("Echo") }, sealedEnvelopeJson);
            foreach (var to in notify.To.ToList())
            {
                DIDCOMMHelpers.SendDIDCOMMMessage(DIDCOMMEndpointUrl, notify.From, to, notify);
            }

            while (Processing)
            {
                foreach (var queue in Queues)
                {
                    string kid = queue.Key;
                    ConcurrentQueue<EncryptedMessage> emessages = queue.Value;
                    while (emessages.Count > 0)
                    {
                        EncryptedMessage emessage = new EncryptedMessage();
                        bool dequeued = emessages.TryDequeue(out emessage);
                        if (dequeued) ProcessEncryptedMessage(emessage);
                    }
                }

                Console.WriteLine("Processing: " + DIDCOMMHelpers.DIDCOMMMessagesSent.ToString() + " DIDCOMM sent. " + DIDCOMMHelpers.HttpMessagesSent.ToString() + " HTTP sent. " + Program.MessagesReceived.ToString() + " HTTP rcvd.");
                Thread.Sleep(100);
            }

            Console.WriteLine("Press Enter to stop DIDCOMM Agent...");
            Console.ReadLine();

            vctpAgent.Stop();
        }

        private static void ProcessEncryptedMessage(EncryptedMessage? emessage)
        {
            EncryptionRecipient r = new EncryptionRecipient();
            r = emessage.Recipients.First<EncryptionRecipient>();
            string kid = r.Header.KeyId;
            string skid = r.Header.SenderKeyId;
            Console.WriteLine("ProcessMessage:" + skid + " to\r\n" + kid);

            var decryptedMessage = DIDComm.Unpack(new UnpackRequest { Message = emessage, SenderKey = KeyVault.Vault[skid].PublicKey, ReceiverKey = KeyVault.Vault[kid].SecretKey });
            var plaintext = decryptedMessage.Plaintext;
            CoreMessage core = new CoreMessage();
            core.MergeFrom(plaintext);
            BasicMessage basic = new BasicMessage();
            basic.MergeFrom(core.Body);
            Console.WriteLine("BasicMessage: " + core.Type + " " + basic.Text);

            ProcessVCTPSMessage(skid, kid, core.Type, basic.Text);
        }

        private static void ProcessVCTPSMessage(string skid, string kid, string type, string message)
        {
            switch (type) // Alice sending a NOTIFY and a VCA
            {
                case VCTPSMessageFactory.NOTIFY: // On receipt, Bob replies with a PULL and VCAACK
                    {
                        var pull = VCTPSMessageFactory.NewPullMsg(kid, new string[] { skid }, vcaackJson);
                        foreach (var to in pull.To.ToList())
                        {
                            DIDCOMMHelpers.SendDIDCOMMMessage(DIDCOMMEndpointUrl, pull.From, to, pull);
                        }
                        break;
                    }
                case VCTPSMessageFactory.PULL: // On receipt, Alice replies with a PUSH, VC and VCAACK
                    {
                        var pull = VCTPSMessageFactory.NewPushMsg(kid, new string[] { skid }, vcaackJson, vcJson);
                        foreach (var to in pull.To.ToList())
                        {
                            DIDCOMMHelpers.SendDIDCOMMMessage(DIDCOMMEndpointUrl, pull.From, to, pull);
                        }
                        break;
                    }
                case VCTPSMessageFactory.PUSH: // On receipt, Bob has received the VC and VCAACK
                    {
                        // New credential received, process it according to processing rights in VCAACK
                        WorkflowEngine.ProcessCredential(); // TODO
                        break;
                    }
                case VCTPSMessageFactory.POLL: // On receipt, Alice (and co.) replues with a NOTIFY and VCA
                    {
                        // TODO
                        break;
                    }
            }
        }
    }
}
