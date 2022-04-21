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
using Trinity;
using Subjects;

namespace VCTPSPrototype2;

class DIDCOMMAgentImplementation : DIDCOMMAgentBase
{
    public override void DIDCOMMEndpointHandler(DIDCOMMMessage request, out DIDCOMMResponse response)
    { 
        DIDCOMMEncryptedMessage encryptedMessage = request.encryptedMessage;

        // Decrypt the DIDCOMMEncryptedMessage from the request
        EncryptedMessage emessage = new EncryptedMessage();
        emessage.Iv = ByteString.FromBase64(encryptedMessage.lv64);
        emessage.Ciphertext = ByteString.FromBase64(encryptedMessage.ciphertext64);
        emessage.Tag = ByteString.FromBase64(encryptedMessage.tag64);
        EncryptionRecipient r = new EncryptionRecipient();
        r.MergeFrom(ByteString.FromBase64(encryptedMessage.recipients64[0]));
        emessage.Recipients.Add(r);

        Console.WriteLine(emessage.Recipients.Count.ToString());
        Console.WriteLine(emessage.Recipients[0].Header.SenderKeyId);
        Console.WriteLine(emessage.Recipients[0].Header.KeyId);

        string skidid = emessage.Recipients[0].Header.SenderKeyId;
        string keyid = emessage.Recipients[0].Header.KeyId;

        var decryptedMessage = DIDComm.Unpack(
          new UnpackRequest { Message = emessage, 
            SenderKey = Program.KeyVault[skidid].MsgPk, ReceiverKey = Program.KeyVault[keyid].MsgSk
          }
        );
        var plaintext = decryptedMessage.Plaintext;
        CoreMessage core = new CoreMessage();
        core.MergeFrom(plaintext);
        BasicMessage basic = new BasicMessage();
        basic.MergeFrom(core.Body);

        // Save the DIDCOMMEncryptedMessage into a LocalStorage
        // 'cell' in TSL adds CellId and causes a value to be assigned to it when it is created (new'ed)
        DIDCOMMEncryptedMessage_Cell encryptedMessageCell = new DIDCOMMEncryptedMessage_Cell(encryptedMessage);
        Global.LocalStorage.SaveDIDCOMMEncryptedMessage_Cell(encryptedMessageCell);
        var celltype = Global.LocalStorage.GetCellType(encryptedMessageCell.CellId);
        ulong cellcount = Global.LocalStorage.CellCount;
        Console.WriteLine("cellid: " + encryptedMessageCell.CellId.ToString() + " celltype: " + celltype.ToString() + " cellcount: " + cellcount);

        response.rc = (int)Trinity.TrinityErrorCode.E_SUCCESS;
    }
}

public class Program
{
    public class SubjectKeys
    {
        public string Name;
        public JsonWebKey MsgPk;    // Identity, Message Encryption/Decryption
        public JsonWebKey MsgSk;    // Identity, Message Encryption/Decryption
        public ByteString ProofPk;  // Creation/Verification of Credential Proofs
        public ByteString ProofSk;  // Creation/Verification of Credential Proofs
    }

    public static Dictionary<string, SubjectKeys> KeyVault = new Dictionary<string, SubjectKeys>();

    static void Main(string[] args)
    {
        Charlie.Initialize();
        Delta.Initialize();
        Echo.Initialize();

        KeyVault.Add(Charlie.KeyId, new SubjectKeys { 
            Name = Charlie.Name, MsgPk = Charlie.PublicKey, MsgSk = Charlie.SecretKey, 
            ProofPk = Charlie.ProofKey.Pk, ProofSk = Charlie.ProofKey.Sk });
        KeyVault.Add(Delta.KeyId, new SubjectKeys { 
            Name = Delta.Name, MsgPk = Delta.PublicKey, MsgSk = Delta.SecretKey,
            ProofPk = Delta.ProofKey.Pk, ProofSk = Delta.ProofKey.Sk });
        KeyVault.Add(Echo.KeyId, new SubjectKeys { 
            Name = Echo.Name, MsgPk = Echo.PublicKey, MsgSk = Echo.SecretKey,
            ProofPk = Echo.ProofKey.Pk, ProofSk = Echo.ProofKey.Sk });

        string vcaJson = Helpers.GetTemplate("VCTPSPrototype2.vca2.json");

        Trinity.TrinityConfig.HttpPort = 8081;
        DIDCOMMAgentImplementation didAgent = new DIDCOMMAgentImplementation();
        didAgent.Start();
        Console.WriteLine("DIDCOMM Agent started...");

        var notify = VCTPSMessageFactory.NewNotifyMsg(
            Charlie.KeyId, new string[] { Delta.KeyId, Echo.KeyId }, vcaJson
        );
        foreach (var tokeyid in notify.To.ToList())
        {
            Console.WriteLine("Sending to: " + KeyVault[tokeyid].Name + "\t" + tokeyid); ;
            var encryptedPackage = DIDComm.Pack(new PackRequest { Plaintext = notify.ToByteString(), SenderKey = Charlie.SecretKey, ReceiverKey = KeyVault[tokeyid].MsgPk, Mode = EncryptionMode.Direct });
            var emessage = encryptedPackage.Message;
            DIDCOMMEncryptedMessage em = new DIDCOMMEncryptedMessage(emessage.Iv.ToBase64(), emessage.Ciphertext.ToBase64(), emessage.Tag.ToBase64(),
                recipients64: new List<string>() { emessage.Recipients[0].ToByteString().ToBase64() });
            DIDCOMMMessage msg = new DIDCOMMMessage(em);
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

        Console.WriteLine("Press Enter to stop DIDCOMM Agent...");
        Console.ReadLine();

        didAgent.Stop();
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