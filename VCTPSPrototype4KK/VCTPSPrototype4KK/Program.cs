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
using Subjects;
using Trinity;

namespace VCTPSPrototype4KK
{ 
    class DIDCommAgentImplementation : DIDCommAgentBase
    {
        public override void DIDCommEndpointHandler(DIDCommMessageRequest request, out DIDCommResponse response)
        {
            DIDCommEncryptedMessage64 didcommEncryptedMessage64 = request.encryptedMessage64;

            EncryptedMessage encryptedMessage = new EncryptedMessage();
            encryptedMessage.Iv = ByteString.FromBase64(didcommEncryptedMessage64.lv64);
            encryptedMessage.Ciphertext = ByteString.FromBase64(didcommEncryptedMessage64.ciphertext64);
            encryptedMessage.Tag = ByteString.FromBase64(didcommEncryptedMessage64.tag64);
            EncryptionRecipient r = new EncryptionRecipient();
            r.MergeFrom(ByteString.FromBase64(didcommEncryptedMessage64.recipients64[0]));
            encryptedMessage.Recipients.Add(r);

            string kid = r.Header.KeyId;
            string skid = r.Header.SenderKeyId;
            Console.WriteLine("DIDCommEndpointHandler: " + skid + " to\r\n" + kid);

            // Persist encryptedMessage
            DIDCommEncryptedMessage_Cell encryptedMessageCell = new DIDCommEncryptedMessage_Cell(didcommEncryptedMessage64);
            // encryptedMessageCell.em = didcommEncryptedMessage64;
            Global.LocalStorage.SaveDIDCommEncryptedMessage_Cell(encryptedMessageCell);
            Global.LocalStorage.SaveStorage();
            var celltype = Global.LocalStorage.GetCellType(encryptedMessageCell.CellId);
            ulong cellcount = Global.LocalStorage.CellCount;
            Console.WriteLine("cellid: " + encryptedMessageCell.CellId.ToString() + " celltype: " + celltype.ToString() + " cellcount: " + cellcount);

            if (!Program.Queues.ContainsKey(kid))
            {
                Program.Queues.TryAdd(kid, new ConcurrentQueue<EncryptedMessage>());
            }
            Program.Queues[kid].Enqueue(encryptedMessage);

            response.rc = (int)Trinity.TrinityErrorCode.E_SUCCESS;

            Program.MessagesReceived++;
            Console.WriteLine("DIDCommEndpointHandler: " 
                + DIDCommHelpers.DIDCommMessageRequestsSent.ToString() + " DIDComm sent. " 
                + DIDCommHelpers.HttpMessagesSent.ToString() + " HTTP sent. "
                + Program.MessagesReceived.ToString() + " HTTP rcvd. "
                + Program.VCsProcessed.ToString() + " VCs proc.");
        }
    }

    public class Program
    {
        public class ActorInfo
        {
            public string Name;
            public JsonWebKey MsgPk;
            public JsonWebKey MsgSk;
            public ByteString ProofPk;
            public ByteString ProofSk;
            public long httpPort;
            public long rpcPort;
        }

        public static ConcurrentDictionary<string, ConcurrentQueue<EncryptedMessage>> Queues =
            new ConcurrentDictionary<string, ConcurrentQueue<EncryptedMessage>>();
        public static bool Processing = true;
        public static Dictionary<string, ActorInfo> KeyVault = new Dictionary<string, ActorInfo>();
        public const string DIDCommEndpointUrl = "http://localhost:8081/DIDCommEndpoint/";
        public static string vcJson;
        public static string vcaJson;
        public static string vcaackJson;
        public static int MessagesReceived = 0;
        public static int VCsProcessed = 0;

        static void Main(string[] args)
        {
            Charlie.Initialize();
            Delta.Initialize();
            Echo.Initialize();

            KeyVault.Add(Charlie.KeyId, new ActorInfo
            {
                Name = Charlie.Name,
                MsgPk = Charlie.PublicKey,
                MsgSk = Charlie.SecretKey,
                ProofPk = Charlie.ProofKey.Pk,
                ProofSk = Charlie.ProofKey.Sk
            });
            KeyVault.Add(Delta.KeyId, new ActorInfo
            {
                Name = Delta.Name,
                MsgPk = Delta.PublicKey,
                MsgSk = Delta.SecretKey,
                ProofPk = Delta.ProofKey.Pk,
                ProofSk = Delta.ProofKey.Sk
            });
            KeyVault.Add(Echo.KeyId, new ActorInfo
            {
                Name = Echo.Name,
                MsgPk = Echo.PublicKey,
                MsgSk = Echo.SecretKey,
                ProofPk = Echo.ProofKey.Pk,
                ProofSk = Echo.ProofKey.Sk
            });

            vcJson = Helpers.GetTemplate("VCTPSPrototype4KK.vc2.json");
            vcaJson = Helpers.GetTemplate("VCTPSPrototype4KK.vca2.json");
            vcaackJson = Helpers.GetTemplate("VCTPSPrototype4KK.vcaack2.json");

            Trinity.TrinityConfig.HttpPort = 8081;
            DIDCommAgentImplementation didAgent = new DIDCommAgentImplementation();
            didAgent.Start();
            Console.WriteLine("DIDComm Agent started...");

            var notify = VCTPSMessageFactory.NewINITIALIZEMsg(Charlie.KeyId, new string[] { Delta.KeyId, Echo.KeyId }, vcaJson);
            DIDCommHelpers.SendDIDCommMessageRequest(DIDCommEndpointUrl, notify);

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

                Console.WriteLine("Processing: "
                    + DIDCommHelpers.DIDCommMessageRequestsSent.ToString() + " DIDComm sent. "
                    + DIDCommHelpers.HttpMessagesSent.ToString() + " HTTP sent. "
                    + Program.MessagesReceived.ToString() + " HTTP rcvd. "
                    + Program.VCsProcessed.ToString() + " VCs proc. (will be < total # messages sent/rcvd)");
                Thread.Sleep(100);
            }

            Console.WriteLine("Press Enter to stop DIDComm Agent...");
            Console.ReadLine();

            didAgent.Stop();
        }

        private static void ProcessEncryptedMessage(EncryptedMessage? encryptedMessage)
        {
            EncryptionRecipient r = new EncryptionRecipient();
            r = encryptedMessage.Recipients.First<EncryptionRecipient>();
            string kid = r.Header.KeyId;
            string skid = r.Header.SenderKeyId;
            Console.WriteLine("ProcessMessage:" + skid + " to\r\n" + kid);

            var unpackResponse = DIDComm.Unpack(new UnpackRequest { Message = encryptedMessage, SenderKey = KeyVault[skid].MsgPk, ReceiverKey = KeyVault[kid].MsgSk });
            var plaintext = unpackResponse.Plaintext;
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
                case VCTPSMessageFactory.INITIALIZE: // On receipt, Bob replies with a PULL and VCAACK
                    {
                        var knockknock = VCTPSMessageFactory.NewKNOCKKNOCKMsg(kid, new string[] { skid }, vcaackJson);
                        DIDCommHelpers.SendDIDCommMessageRequest(DIDCommEndpointUrl, knockknock);
                        break;
                    }
                case VCTPSMessageFactory.KNOCKKNOCK: // On receipt, Alice replies with a PUSH, VC and VCAACK
                    {
                        var whoisthere = VCTPSMessageFactory.NewWHOISTHEREMsg(kid, new string[] { skid }, vcaackJson, vcJson);
                        DIDCommHelpers.SendDIDCommMessageRequest(DIDCommEndpointUrl, whoisthere);
                        break;
                    }
                case VCTPSMessageFactory.WHOISTHERE: // On receipt, Bob has received the VC and VCAACK
                    {
                        // New credential received, process it according to processing rights in VCAACK
                        // WorkflowEngine.ProcessCredential(); // TODO
                        // VCsProcessed++;

                        var itsme = VCTPSMessageFactory.NewITSMEMsg(kid, new string[] { skid }, -1); // TODO
                        DIDCommHelpers.SendDIDCommMessageRequest(DIDCommEndpointUrl, itsme);
                        break;
                    }
                case VCTPSMessageFactory.ITSME: // On receipt, Alice (and co.) replies with a NOTIFY and VCA
                    {
                        break;
                    }
            }
        }
    }
}
