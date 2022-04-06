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

namespace VCTPSPrototype3;

class VCTPSAgentImplementation : VCTPSAgentBase
{
    public override void DIDCOMMEndpointHandler(VCTPSMessage request, out VCTPSResponse response)
    {
        VCTPSEncryptedMessage encryptedMessage = request.encryptedMessage;

        EncryptedMessage emessage = new EncryptedMessage();
        emessage.Iv = ByteString.FromBase64(encryptedMessage.lv64);
        emessage.Ciphertext = ByteString.FromBase64(encryptedMessage.ciphertext64);
        emessage.Tag = ByteString.FromBase64(encryptedMessage.tag64);
        EncryptionRecipient r = new EncryptionRecipient();
        r.MergeFrom(ByteString.FromBase64(encryptedMessage.recipients64[0]));
        emessage.Recipients.Add(r);

        var decryptedMessage = DIDComm.Unpack(new UnpackRequest { Message = emessage, SenderKey = Actors.Charlie.PublicKey, ReceiverKey = Actors.Delta.SecretKey });
        var plaintext = decryptedMessage.Plaintext;
        CoreMessage core = new CoreMessage();
        core.MergeFrom(plaintext);
        BasicMessage basic = new BasicMessage();
        basic.MergeFrom(core.Body);

        response.rc = (int)Trinity.TrinityErrorCode.E_SUCCESS;
    }
}

public class Program
{
    class ActorInfo
    {
        public string Name;
        public JsonWebKey MsgPk;
        public JsonWebKey MsgSk;
        public long httpPort;
        public long rpcPort;
        public ByteString ProofPk;
        public ByteString ProofSk;
    }

    static void Main(string[] args)
    {
        Actors.Charlie.Initialize();
        Actors.Delta.Initialize();
        Actors.Echo.Initialize();

        Dictionary<string,ActorInfo> actors = new Dictionary<string, ActorInfo>();
        actors.Add(Actors.Charlie.KeyId, new ActorInfo { Name = Actors.Charlie.Name, MsgPk = Actors.Charlie.PublicKey, MsgSk = Actors.Charlie.SecretKey, 
                    ProofPk = Actors.Charlie.ProofKey.Pk, ProofSk = Actors.Charlie.ProofKey.Sk });
        actors.Add(Actors.Delta.KeyId, new ActorInfo { Name = Actors.Delta.Name, MsgPk = Actors.Delta.PublicKey, MsgSk = Actors.Delta.SecretKey,
                    ProofPk = Actors.Delta.ProofKey.Pk, ProofSk = Actors.Delta.ProofKey.Sk });
        actors.Add(Actors.Echo.KeyId, new ActorInfo { Name = Actors.Echo.Name, MsgPk = Actors.Echo.PublicKey, MsgSk = Actors.Echo.SecretKey,
                    ProofPk = Actors.Echo.ProofKey.Pk, ProofSk = Actors.Echo.ProofKey.Sk });

        string vcaJson = Helpers.GetTemplate("VCTPSPrototype3.vca2.json");

        Trinity.TrinityConfig.HttpPort = 8081;
        VCTPSAgentImplementation vctpAgent = new VCTPSAgentImplementation();
        vctpAgent.Start();
        Console.WriteLine("VCTPS Agent started...");

        var notify = VCTPSMessageFactory.NewNotifyMsg(Actors.Charlie.KeyId, new string[] { Actors.Delta.KeyId, Actors.Echo.KeyId }, vcaJson);
        foreach (var to in notify.To.ToList())
        {
            Console.WriteLine("Sending to: " + actors[to].Name + "\t" + to); ;
            var encryptedPackage = DIDComm.Pack(new PackRequest { Plaintext = notify.ToByteString(), SenderKey = Actors.Charlie.SecretKey, ReceiverKey = actors[to].MsgPk, Mode = EncryptionMode.Direct });
            var emessage = encryptedPackage.Message;
            VCTPSEncryptedMessage em = new VCTPSEncryptedMessage(emessage.Iv.ToBase64(), emessage.Ciphertext.ToBase64(), emessage.Tag.ToBase64(),
                recipients64: new List<string>() { emessage.Recipients[0].ToByteString().ToBase64() });
            VCTPSMessage msg = new VCTPSMessage(em);
            var emJson = msg.ToString();

            using (var httpClient = new HttpClient())
            {
                string agentUrl = "http://localhost:8081/DIDCOMMEndpoint/";
                Console.WriteLine(">>>Agent Url:" + agentUrl);
                using (var requestMessage = new HttpRequestMessage(new HttpMethod("POST"), agentUrl))
                {
                    requestMessage.Headers.TryAddWithoutValidation("Accept", "application/json");
                    Console.WriteLine(">>>Payload:" + emJson);
                    requestMessage.Content = new StringContent(emJson);
                    var task = httpClient.SendAsync(requestMessage);
                    task.Wait();
                    var result = task.Result;
                    string jsonResponse = result.Content.ReadAsStringAsync().Result;
                    Console.WriteLine(">>>Response:" + jsonResponse);
                }
            }
        }

        Console.WriteLine("Press Enter to stop VCTPS Agent...");
        Console.ReadLine();

        vctpAgent.Stop();
    }
}

/* emessage:
{
    "iv": "eJwEmTlycyaThqwc72Ra9/5dfU/DcfpF",
    "ciphertext": "Gis5eT7nFQk5bD2Lj3xRHvZbRDb0stxG6OyvcMZUYW0FomdRVi9v/yGnfnKDgxO0/ZtzhnhjbuZ91N+6N//KpgUCR7UGBO253+5+NkjMxUMaqyvWZ2F2cXvXidjNmvG/Q/W0QnlqmAA4kQirxVsZJGUhe23pl+G6IQJA9Y7l7PBmDVANZN+HmdzOwKHpsX78Pk5L57hOu2xgaJXOe9AaoWbG18+QdZspMTWXCLeTUH/QbRpc0ZXHZbJ8PKFleqs4hlE3sJWgH2uL6F9fs6EM6rp4YcMfbrtwiVDLbaK8kBYOfGeJOTGhdN3FfAKU0/gVNgK+n5R3ff2jd41fEWvZ61w5AnPFwH15NDe7PtjO7TsWjDzKC+4YMKR5soiOVRNPqtFHbXp6r/wuqliLOOly9bHF7xXo93NUdEraWL5AUE+TqD5q7eqle5rSzYr8eVYjqh5Q8NKbsPjJcrhqVs+USfk4gsk5TagpSSvwKMLYg7v6gppTl2CdMA/j3NPnkyj7qpEmRIE0PhOSoe6orpK+NxxKuXg+TYmfocBDhbD4bdbB6rnEBKjSEA1NjXXXtJz2HLmlPpwiuRXy58CNFx4zzQRe7A8=",
    "tag": "O/vo05SsIwvgVVczruzTew==",
    "recipients": [
        {
            "unprotected": {
                "kid": "did:key:z6LSjNJkeDgNYHzdwWhJrq8yMUswoGYRbwt9vZFiV9xh6kb1#z6LSjNJkeDgNYHzdwWhJrq8yMUswoGYRbwt9vZFiV9xh6kb1",
                "skid": "did:key:z6LSprVN4NQZsDLyLfXbSxGKR7cLXKZTDDrzrLz3iridET43#z6LSprVN4NQZsDLyLfXbSxGKR7cLXKZTDDrzrLz3iridET43"
            }
        }
    ]
}
*/