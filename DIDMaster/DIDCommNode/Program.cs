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
using System.Net.Http;
using System.Net.Http.Headers;
using System.ComponentModel.Design;
using Trinity;
using Subjects;

namespace DIDCommNode
{

    class DIDCommAgentImplementation : DIDCommAgentBase
    {
        public override void DIDCommEndpointHandler(DIDCommMessageRequest request, out DIDCommResponse response)
        {
            // TODO
            response.rc = (int)401; // Trinity.TrinityErrorCode.E_SUCCESS;
        }

        public override void DoorKnockerHandler(DoorKnockerMessageRequest request, out DoorKnockerResponse response)
        {
            // TODO
            response.rc = (int)402; // Trinity.TrinityErrorCode.E_SUCCESS;
        }
    }

    public class Program
    {
        const int masterPort = 0;

        static void Main(string[] args)
        {
            if (args.Length != 4)
            {
                string msg = "DIDCommNode: DIDCommNode.exe masterPort personName personEmail nodePort";
                Console.WriteLine(msg);
                Console.WriteLine("Press Enter to stop DIDCommNode.exe...");
                Console.ReadLine();
            }
            int masterPort = int.Parse(args[0]);
            string personName = args[1];
            string personEmail = args[2];
            int nodePort = int.Parse(args[3]);
            Console.WriteLine("DIDCommNode: " + masterPort.ToString() + " " + personName + " " + personEmail + " " + " " + nodePort.ToString());
            Console.ReadLine();

            DIDDocument didDocument = Subjects.MyPersonification.GetKeys("", personName, "localhost", nodePort, true);
            Console.WriteLine("KeyId: " + MyPersonification.KeyId);

            TrinityConfig.HttpPort = nodePort;
#pragma warning disable CS0612 // Type or member is obsolete
            TrinityConfig.ServerPort = nodePort + 1;
#pragma warning restore CS0612 // Type or member is obsolete
            DIDCommAgentImplementation didAgent = new DIDCommAgentImplementation();
            didAgent.Start();
            Console.WriteLine("DIDCommNode.exe started...");

            KnockKnockDoc doc = new KnockKnockDoc();
            doc.action = "knockknock.initialize";
            doc.from = personEmail;
            doc.correlationId = "DIDCommNode";
            doc.senderDIDDoc = didDocument;

            string emJson = doc.ToString();

            Console.WriteLine("Press Enter after attaching Debugger to DIDCommNode.exe...");
            Console.ReadLine();

            System.Diagnostics.Debugger.Break();
            using (var httpClient = new HttpClient())
            {
                string agentUrl = "http://localhost:" + masterPort.ToString() + "/DockerKnocker/";
                Console.WriteLine("DIDCommNode.Agent Url:" + agentUrl);
                using (var requestMessage = new HttpRequestMessage(new HttpMethod("POST"), agentUrl))
                {
                    requestMessage.Headers.TryAddWithoutValidation("Accept", "application/json");
                    Console.WriteLine("DIDCommNode.Payload:" + emJson);
                    requestMessage.Content = new StringContent(emJson);
                    var task = httpClient.SendAsync(requestMessage);
                    task.Wait();
                    var result = task.Result;
                    string jsonResponse = result.Content.ReadAsStringAsync().Result;
                    Console.WriteLine("DIDCommNode.Response:" + jsonResponse);
                    DoorKnockerResponse response = new DoorKnockerResponse();
                    DoorKnockerResponse.TryParse(jsonResponse, out response);
                    Console.WriteLine("DIDCommNode.Response:" + response.ToString());
                }
            }

            Console.WriteLine("Press Enter to stop DIDCommNode.exe...");
            Console.ReadLine();

            didAgent.Stop();
        }
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