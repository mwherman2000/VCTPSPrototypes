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

namespace DIDCommAgent
{

    class DIDCOMMAgentImplementation : DIDCOMMAgentBase
    {
        public override void DIDCOMMEndpointHandler(DIDCOMMMessage request, out DIDCOMMResponse response)
        {
            // TODO
            response.rc = (int)200; // Trinity.TrinityErrorCode.E_SUCCESS;
        }

        public override void DoorKnockerHandler(DoorKnockerMessage request, out DoorKnockerResponse response)
        {
            // TODO
            response.rc = (int)200; // Trinity.TrinityErrorCode.E_SUCCESS;
        }
    }

    public class Program
    {
        const int masterPort = 0;

        static void Main(string[] args)
        {
            if (args.Length != 4)
            {
                string msg = "DIDCommAgent: DIDCommAgent.exe masterPort personName personEmail agentPort";
                Console.WriteLine(msg);
                Console.WriteLine("Press Enter to stop DIDCommAgent.exe...");
                Console.ReadLine();
            }
            int masterPort = int.Parse(args[0]);
            string personName = args[1];
            string personEmail = args[2];
            int agentPort = int.Parse(args[3]);

            TrinityConfig.HttpPort = agentPort;
#pragma warning disable CS0612 // Type or member is obsolete
            TrinityConfig.ServerPort = agentPort + 1;
#pragma warning restore CS0612 // Type or member is obsolete
            DIDCOMMAgentImplementation didAgent = new DIDCOMMAgentImplementation();
            didAgent.Start();
            Console.WriteLine("DIDCommAgent.exe started...");

            DIDDocument didDocument = Subjects.SubjectFactory.Initialize(personName, "localhost", agentPort);
            string emJson = didDocument.ToString(); // TODO HACK

            using (var httpClient = new HttpClient())
            {
                string agentUrl = "http://localhost:" + masterPort.ToString() + "/DockerKnocker/";
                Console.WriteLine("DIDCommAgent.Agent Url:" + agentUrl);
                using (var requestMessage = new HttpRequestMessage(new HttpMethod("POST"), agentUrl))
                {
                    requestMessage.Headers.TryAddWithoutValidation("Accept", "application/json");
                    Console.WriteLine("DIDCommAgent.Payload:" + emJson);
                    requestMessage.Content = new StringContent(emJson);
                    var task = httpClient.SendAsync(requestMessage);
                    task.Wait();
                    var result = task.Result;
                    string jsonResponse = result.Content.ReadAsStringAsync().Result;
                    Console.WriteLine("DIDCommAgent.Response:" + jsonResponse);
                }
            }

            Console.WriteLine("Press Enter to stop DIDCommAgent.exe...");
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