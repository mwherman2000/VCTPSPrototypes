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
using System.Collections.Generic;
using System.Threading;
using System.Linq;

namespace VCTPSPrototype4KK
{ 
    class DIDCommAgentImplementation : DIDCommAgentBase
    {
        public override void DIDCommEndpointHandler(DIDCommMessageRequest request, out DIDCommResponse response)
        {
            DIDCommEncryptedMessage64 didcommEncryptedMessage64 = request.encryptedMessage64;

            EncryptionRecipient r = new EncryptionRecipient();
            r.MergeFrom(ByteString.FromBase64(didcommEncryptedMessage64.recipients64[0]));
            string rkid = r.Header.KeyId;
            string skid = r.Header.SenderKeyId;
            Console.WriteLine("DIDCommEndpointHandler: " + skid + " to\r\n" + rkid);

            // Persist encryptedMessage
            DIDCommEncryptedMessage64_Cell encryptedMessage64Cell = new DIDCommEncryptedMessage64_Cell(didcommEncryptedMessage64);
            Global.LocalStorage.SaveDIDCommEncryptedMessage64_Cell(encryptedMessage64Cell);
            Global.LocalStorage.SaveStorage();
            var celltype = Global.LocalStorage.GetCellType(encryptedMessage64Cell.CellId);
            ulong cellcount = Global.LocalStorage.CellCount;
            Console.WriteLine("cellid: " + encryptedMessage64Cell.CellId.ToString() + " celltype: " + celltype.ToString() + " cellcount: " + cellcount);

            if (!Program.Queues.ContainsKey(rkid))
            {
                Program.Queues.TryAdd(rkid, new ConcurrentQueue<long>());
            }
            Program.Queues[rkid].Enqueue(encryptedMessage64Cell.CellId);

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
            public JsonWebKey PublicKey;
            public JsonWebKey SecretKey;
            public ByteString ProofKeyPk;
            public ByteString ProofKeySk;
            public long httpPort;
            public long rpcPort;
        }

        public static ConcurrentDictionary<string, ConcurrentQueue<long>> Queues =
            new ConcurrentDictionary<string, ConcurrentQueue<long>>();
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
            Charlie.Initialize("localhost", 8080);
            Delta.Initialize("localhost", 8084);
            Echo.Initialize("localhost", 8088);

            KeyVault.Add(Charlie.KeyId, new ActorInfo
            {
                Name = Charlie.Name,
                PublicKey = Charlie.PublicKey,
                SecretKey = Charlie.SecretKey,
                ProofKeyPk = Charlie.ProofKey.Pk,
                ProofKeySk = Charlie.ProofKey.Sk
            });
            KeyVault.Add(Delta.KeyId, new ActorInfo
            {
                Name = Delta.Name,
                PublicKey = Delta.PublicKey,
                SecretKey = Delta.SecretKey,
                ProofKeyPk = Delta.ProofKey.Pk,
                ProofKeySk = Delta.ProofKey.Sk
            });
            KeyVault.Add(Echo.KeyId, new ActorInfo
            {
                Name = Echo.Name,
                PublicKey = Echo.PublicKey,
                SecretKey = Echo.SecretKey,
                ProofKeyPk = Echo.ProofKey.Pk,
                ProofKeySk = Echo.ProofKey.Sk
            });

            vcJson = Helpers.GetTemplate("VCTPSPrototype4KK.vc2.json");
            vcaJson = Helpers.GetTemplate("VCTPSPrototype4KK.vca2.json");
            vcaackJson = Helpers.GetTemplate("VCTPSPrototype4KK.vcaack2.json");

            Trinity.TrinityConfig.HttpPort = 8081;
            DIDCommAgentImplementation didAgent = new DIDCommAgentImplementation();
            didAgent.Start();
            Console.WriteLine("DIDComm Agent started...");

            var msg = MessageFactory.NewINITIALIZEMsg(Charlie.KeyId, new string[] { Delta.KeyId, Echo.KeyId }, vcaJson);
            DIDCommHelpers.SendDIDCommMessageRequest(DIDCommEndpointUrl, msg);

            while (Processing)
            {
                foreach (var queue in Queues)
                {
                    //string rkidkey = queue.Key;
                    ConcurrentQueue<long> cellids = queue.Value;
                    while (cellids.Count > 0)
                    {
                        long cellid;
                        bool dequeued = cellids.TryDequeue(out cellid);
                        if (dequeued)
                        {
                            DIDCommEncryptedMessage64_Cell encryptedMessage64Cell = Global.LocalStorage.LoadDIDCommEncryptedMessage64_Cell(cellid);

                            DIDCommEncryptedMessage64 didcommEncryptedMessage64 = encryptedMessage64Cell.em;

                            EncryptionRecipient r = new EncryptionRecipient();
                            r.MergeFrom(ByteString.FromBase64(didcommEncryptedMessage64.recipients64[0]));
                            string rkid = r.Header.KeyId;
                            string skid = r.Header.SenderKeyId;
                            Console.WriteLine("Main:Dequeue: " + skid + " to\r\n" + rkid);

                            EncryptedMessage encryptedMessage = new EncryptedMessage();
                            encryptedMessage.Iv = ByteString.FromBase64(didcommEncryptedMessage64.lv64);
                            encryptedMessage.Ciphertext = ByteString.FromBase64(didcommEncryptedMessage64.ciphertext64);
                            encryptedMessage.Tag = ByteString.FromBase64(didcommEncryptedMessage64.tag64);
                            encryptedMessage.Recipients.Add(r);

                            ProcessEncryptedMessage(encryptedMessage);
                        }
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
            string rkid = r.Header.KeyId;
            string skid = r.Header.SenderKeyId;
            Console.WriteLine("ProcessEncryptedMessage:" + skid + " to\r\n" + rkid);

            var unpackResponse = DIDComm.Unpack(new UnpackRequest { Message = encryptedMessage, SenderKey = KeyVault[skid].PublicKey, ReceiverKey = KeyVault[rkid].SecretKey });
            var plaintext = unpackResponse.Plaintext;
            CoreMessage core = new CoreMessage();
            core.MergeFrom(plaintext);
            BasicMessage basic = new BasicMessage();
            basic.MergeFrom(core.Body);
            Console.WriteLine("BasicMessage: " + core.Type + " " + basic.Text);

            ProcessBasicMessage(skid, rkid, core.Type, basic.Text);
        }

        private static void ProcessBasicMessage(string skid, string rkid, string type, string message)
        {
            switch (type) // Alice sending a NOTIFY and a VCA
            {
                case MessageFactory.INITIALIZE: // On receipt, Bob replies with a PULL and VCAACK
                    {
                        var knockknock = MessageFactory.NewKNOCKKNOCKMsg(rkid, new string[] { skid }, vcaackJson);
                        DIDCommHelpers.SendDIDCommMessageRequest(DIDCommEndpointUrl, knockknock);
                        break;
                    }
                case MessageFactory.KNOCKKNOCK: // On receipt, Alice replies with a PUSH, VC and VCAACK
                    {
                        var whoisthere = MessageFactory.NewWHOISTHEREMsg(rkid, new string[] { skid }, vcaackJson, vcJson);
                        DIDCommHelpers.SendDIDCommMessageRequest(DIDCommEndpointUrl, whoisthere);
                        break;
                    }
                case MessageFactory.WHOISTHERE: // On receipt, Bob has received the VC and VCAACK
                    {
                        // New credential received, process it according to processing rights in VCAACK
                        // WorkflowEngine.ProcessCredential(); // TODO
                        // VCsProcessed++;

                        var itsme = MessageFactory.NewITSMEMsg(rkid, new string[] { skid }, -1); // TODO
                        DIDCommHelpers.SendDIDCommMessageRequest(DIDCommEndpointUrl, itsme);
                        break;
                    }
                case MessageFactory.ITSME: // On receipt, Alice (and co.) replies with a NOTIFY and VCA
                    {
                        break;
                    }
            }
        }
    }
}
