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

namespace VCTPSPrototype4;

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
        Console.WriteLine("DIDCOMMEndpointHandler: " + Helpers.DIDCOMMMessagesSent.ToString() + " DIDCOMM sent. " + Helpers.HttpMessagesSent.ToString() + " HTTP sent. " + Program.MessagesReceived.ToString() + " HTTP rcvd.");
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

    public static Dictionary<string, ConcurrentQueue<EncryptedMessage>> Queues = new Dictionary<string, ConcurrentQueue<EncryptedMessage>>();
    public static bool Processing = true;
    public static Dictionary<string, ActorInfo> KeyVault = new Dictionary<string, ActorInfo>();
    public const string DIDCOMMEndpointUrl = "http://localhost:8081/DIDCOMMEndpoint/";
    public static string vcJson;
    public static string vcaJson;
    public static string vcaackJson;
    public static int MessagesReceived = 0;

    static void Main(string[] args)
    {
        Actors.Charlie.Initialize();
        Actors.Delta.Initialize();
        Actors.Echo.Initialize();

        KeyVault.Add(Actors.Charlie.KeyId, new ActorInfo { Name = Actors.Charlie.Name, MsgPk = Actors.Charlie.PublicKey, MsgSk = Actors.Charlie.SecretKey, 
                    ProofPk = Actors.Charlie.ProofKey.Pk, ProofSk = Actors.Charlie.ProofKey.Sk });
        KeyVault.Add(Actors.Delta.KeyId, new ActorInfo { Name = Actors.Delta.Name, MsgPk = Actors.Delta.PublicKey, MsgSk = Actors.Delta.SecretKey,
                    ProofPk = Actors.Delta.ProofKey.Pk, ProofSk = Actors.Delta.ProofKey.Sk });
        KeyVault.Add(Actors.Echo.KeyId, new ActorInfo { Name = Actors.Echo.Name, MsgPk = Actors.Echo.PublicKey, MsgSk = Actors.Echo.SecretKey,
                    ProofPk = Actors.Echo.ProofKey.Pk, ProofSk = Actors.Echo.ProofKey.Sk });

        vcJson = Helpers.GetTemplate("VCTPSPrototype4.vc2.json");
        vcaJson = Helpers.GetTemplate("VCTPSPrototype4.vca2.json");
        vcaackJson = Helpers.GetTemplate("VCTPSPrototype4.vcaack2.json");

        Trinity.TrinityConfig.HttpPort = 8081;
        DIDCOMMAgentImplementation didAgent = new DIDCOMMAgentImplementation();
        didAgent.Start();
        Console.WriteLine("DIDCOMM Agent started...");

        var notify = VCTPSMessageFactory.NewNotifyMsg(Actors.Charlie.KeyId, new string[] { Actors.Delta.KeyId, Actors.Echo.KeyId }, vcaJson);
        foreach (var to in notify.To.ToList())
        {
            Helpers.SendDIDCOMMMessage(DIDCOMMEndpointUrl, notify.From, to, notify );
        }

        while(Processing)
        {
            foreach(var queue in Queues)
            {
                string kid = queue.Key;
                ConcurrentQueue<EncryptedMessage> emessages = queue.Value;
                while(emessages.Count > 0)
                {
                    EncryptedMessage emessage = new EncryptedMessage();       
                    bool dequeued = emessages.TryDequeue(out emessage);
                    if (dequeued) ProcessEncryptedMessage(emessage);
                }
            }

            Console.WriteLine("Processing: " + Helpers.DIDCOMMMessagesSent.ToString() + " DIDCOMM sent. " + Helpers.HttpMessagesSent.ToString() + " HTTP sent. " + Program.MessagesReceived.ToString() + " HTTP rcvd.");
            Thread.Sleep(100);
        }

        Console.WriteLine("Press Enter to stop DIDCOMM Agent...");
        Console.ReadLine();

        didAgent.Stop();
    }

    private static void ProcessEncryptedMessage(EncryptedMessage? emessage)
    {
        EncryptionRecipient r = new EncryptionRecipient();
        r = emessage.Recipients.First<EncryptionRecipient>();   
        string kid = r.Header.KeyId;
        string skid = r.Header.SenderKeyId;
        Console.WriteLine("ProcessMessage:" + skid + " to\r\n" + kid);

        var decryptedMessage = DIDComm.Unpack(new UnpackRequest { Message = emessage, SenderKey = KeyVault[skid].MsgPk, ReceiverKey = KeyVault[kid].MsgSk });
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
                        Helpers.SendDIDCOMMMessage(DIDCOMMEndpointUrl, pull.From, to, pull);
                    }
                    break;
                }
            case VCTPSMessageFactory.PULL: // On receipt, Alice replies with a PUSH, VC and VCAACK
                {
                    var pull = VCTPSMessageFactory.NewPushMsg(kid, new string[] { skid }, vcaackJson, vcJson);
                    foreach (var to in pull.To.ToList())
                    {
                        Helpers.SendDIDCOMMMessage(DIDCOMMEndpointUrl, pull.From, to, pull);
                    }
                    break;
                }
            case VCTPSMessageFactory.PUSH: // On receipt, Bob has received the VC and VCAACK
                {
                    // New credential received, process it according to processing rights in VCAACK
                    WorkflowEngine.ProcessCredential(); // TODO
                    break;
                }
            case VCTPSMessageFactory.POLL: // On receipt, Alice (and co.) replies with a NOTIFY and VCA
                {
                    break;
                }
        }
    }
}
