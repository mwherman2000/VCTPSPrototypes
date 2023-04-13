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
using Subjects;

namespace DIDMaster
{

    class DIDCommAgentImplementation : DIDCommAgentBase
    {
        public override void DIDCommEndpointHandler(DIDCommMessageRequest request, out DIDCommResponse response)
        {
            // TODO
            Console.WriteLine("DIDMaster.exe: DIDCommEndpointHandler");
            response.rc = (int)201; // Trinity.TrinityErrorCode.E_SUCCESS;
        }

        public override void DoorKnockerHandler(DoorKnockerMessageRequest request, out DoorKnockerResponse response)
        {
            // TODO
            Console.WriteLine("DIDMaster.exe: DoorKnockerHandler");
            response.rc = (int)202; // Trinity.TrinityErrorCode.E_SUCCESS;
        }
    }

    public class Program
    {
        const int masterPort = 0;

        static void Main(string[] args)
        {
            if (args.Length != 5)
            {
                string msg = "DIDMaster: didmaster masterPort personName personEmail agentPort nodePort";
                Console.WriteLine(msg);
                throw new ArgumentException(msg);
            }
            int masterPort = int.Parse(args[0]);
            string personName = args[1];
            string personEmail = args[2];
            int agentPort = int.Parse(args[3]);
            int nodePort = int.Parse(args[4]);
            Console.WriteLine("DIDMaster: " + masterPort.ToString() + " " + personName + " " + personEmail + " " + agentPort.ToString() + " " + nodePort.ToString());
            Console.ReadLine();

            DIDDocument didDocument = Subjects.MyPersonification.GetDIDDocument("", personName, "localhost", masterPort, true);
            Console.WriteLine("KeyId:\t" + MyPersonification.KeyId);
            Console.WriteLine("Id:\t" + didDocument.id);
            string did = DidWeb7Method.NewDid(didDocument);
            Console.WriteLine("did:\t" + did);

            Trinity.TrinityConfig.HttpPort = masterPort;
            DIDCommAgentImplementation didAgent = new DIDCommAgentImplementation();
            didAgent.Start();
            Console.WriteLine("DIDMaster.exe started...");

            string emJson = "{ \"msg\" : \"DIDMaster.exe starting\" }"; // dummy message

            using (var httpClient = new HttpClient())
            {
                string agentUrl = "http://localhost:" + masterPort.ToString() + "/DIDCommEndpoint/";
                Console.WriteLine("DIDMaster.Agent Url:" + agentUrl);
                using (var requestMessage = new HttpRequestMessage(new HttpMethod("POST"), agentUrl))
                {
                    requestMessage.Headers.TryAddWithoutValidation("Accept", "application/json");
                    Console.WriteLine("DIDMaster.Payload:" + emJson);
                    requestMessage.Content = new StringContent(emJson);
                    var task = httpClient.SendAsync(requestMessage);
                    task.Wait();
                    var result = task.Result;
                    string jsonResponse = result.Content.ReadAsStringAsync().Result;
                    Console.WriteLine("DIDMaster.Response:" + jsonResponse);
                }
            }

            using (var httpClient = new HttpClient())
            {
                string agentUrl = "http://localhost:" + masterPort.ToString() + "/DoorKnocker/";
                Console.WriteLine("DIDMaster.Agent Url:" + agentUrl);
                using (var requestMessage = new HttpRequestMessage(new HttpMethod("POST"), agentUrl))
                {
                    requestMessage.Headers.TryAddWithoutValidation("Accept", "application/json");
                    Console.WriteLine("DIDMaster.Payload:" + emJson);
                    requestMessage.Content = new StringContent(emJson);
                    var task = httpClient.SendAsync(requestMessage);
                    task.Wait();
                    var result = task.Result;
                    string jsonResponse = result.Content.ReadAsStringAsync().Result;
                    Console.WriteLine("DIDMaster.Response:" + jsonResponse);
                }
            }

            personName = "\"Alice Allison\"";
            personEmail = "alicemallison@gmail.com";
            agentPort = 8082;
            nodePort = 8084;
            ExecuteAsAdmin("C:\\TDW\\repos\\VCTPSPrototypes\\DIDMaster\\DIDCommAgent\\bin\\Debug\\net6.0\\DIDCommAgent.exe", masterPort.ToString() + " " + personName + " " + personEmail + " " + agentPort.ToString());
            ExecuteAsAdmin("C:\\TDW\\repos\\VCTPSPrototypes\\DIDMaster\\DIDCommNode\\bin\\Debug\\net6.0\\DIDCommNode.exe", masterPort.ToString() + " " + personName + " " + personEmail + " " + nodePort.ToString());

            personName = "\"Robert (Bob) Roberts\"";
            personEmail = "roberthroberts@gmail.com";
            agentPort = 8086;
            nodePort = 8088;
            ExecuteAsAdmin("..\\..\\..\\..\\DIDCommAgent\\bin\\Debug\\net6.0\\DIDCommAgent.exe", masterPort.ToString() + " " + personName + " " + personEmail + " " + agentPort.ToString());
            ExecuteAsAdmin("..\\..\\..\\..\\DIDCommNode\\bin\\Debug\\net6.0\\DIDCommNode.exe", masterPort.ToString() + " " + personName + " " + personEmail + " " + nodePort.ToString());

            Console.WriteLine("Press Enter to stop DIDMaster.exe and kill child processes...");
            Console.ReadLine();

            EndProcessTree("DIDCommNode.exe");
            EndProcessTree("DIDCommAgent.exe");
            EndProcessTree("DIDMaster.exe");

            Console.WriteLine("Press Enter to stop DIDMaster.exe...");
            Console.ReadLine();

            didAgent.Stop();
        }

        static void ExecuteAsAdmin(string fileName, string arguments)
        {
            Process proc = new Process();
            proc.StartInfo.FileName = fileName;
            proc.StartInfo.UseShellExecute = true;
            proc.StartInfo.Verb = "runas";
            proc.StartInfo.Arguments = arguments;
            proc.Start();
        }

        static void EndProcessTree(string imageFilename)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo()
            {
                FileName = "taskkill",
                Arguments = $"/im {imageFilename} /f /t",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            Process.Start(startInfo).WaitForExit();
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