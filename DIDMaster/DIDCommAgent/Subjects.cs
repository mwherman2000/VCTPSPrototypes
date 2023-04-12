using System;
using System.IO;
using Okapi.Keys;
using Okapi.Keys.V1;
using System.Text.Json;
using Okapi.Security;
using Okapi.Security.V1;
using System.Text.Json.Nodes;
using Google.Protobuf.WellKnownTypes;

using DIDCommAgent;
using System.Collections.Generic;
using System.Reflection.Metadata.Ecma335;

namespace Subjects
{
    public static class MyPersonification
    {
        public static bool IsInitialized = false;
        public static JsonWebKey SecretKey = new JsonWebKey();
        public static JsonWebKey PublicKey = new JsonWebKey();
        public static string KeyId;
        public static CreateOberonKeyResponse ProofKey;

        public static DIDDocument Initialize(string personName, string host, int port)
        {
            DIDDocument didDocument = new DIDDocument();

            string keyFilename = "c:\\temp\\" + personName + ".keystore.json";      // new filename
            string keyFilename2 = "c:\\temp\\" + personName + ".diddocstore.json";  // new filename

            //File.Delete(keyFilename);
            //File.Delete(keyFilename2);

            JsonWebKey didWebKey;
            GenerateKeyResponse didKey;
            if (!File.Exists(keyFilename) || !File.Exists(keyFilename2))
            {
                didKey = DIDKey.Generate(new GenerateKeyRequest { KeyType = KeyType.X25519 });

                didWebKey = didKey.Key[0];
                string didWebKeyJson = JsonSerializer.Serialize(didWebKey);
                File.WriteAllText(keyFilename, didWebKeyJson);

                JsonNode jsonDoc = JsonNode.Parse(didKey.DidDocument.ToString());
                var options = new JsonSerializerOptions { WriteIndented = true };
                Console.WriteLine(personName + ": " + jsonDoc.ToJsonString(options));
                //          {
                //              "keyAgreement": [
                // "did:key:z6LSqnPgEUmpUsmdiiyuDo5ZGn9EsegGYwE7x8emiL6dJAyQ#z6LSqnPgEUmpUsmdiiyuDo5ZGn9EsegGYwE7x8emiL6dJAyQ"
                //                                ],
                //              "id": "did:key:z6LSqnPgEUmpUsmdiiyuDo5ZGn9EsegGYwE7x8emiL6dJAyQ",
                //              "@context": "https://www.w3.org/ns/did/v1",
                //              "verificationMethod": [
                //                  {
                //                    "type": "X25519KeyAgreementKey2019",
                //                    "publicKeyBase58": "F7DWiAxxPR3tdLc8h9ZbxBvm2W99rL3y59w6DsT6aoCe",
                //                    "id":
                // "did:key:z6LSqnPgEUmpUsmdiiyuDo5ZGn9EsegGYwE7x8emiL6dJAyQ#z6LSqnPgEUmpUsmdiiyuDo5ZGn9EsegGYwE7x8emiL6dJAyQ",
                //                    "controller": "did:key:z6LSqnPgEUmpUsmdiiyuDo5ZGn9EsegGYwE7x8emiL6dJAyQ",
                //                    "privateKeyBase58": "GdpF2ANVJLKa1er1NFAGUVwWkh99wEdRJccybCBmUmUg"
                //                  }
                //               ]
                //          }

                didDocument = new DIDDocument();
                didDocument.id = jsonDoc["id"].ToString();
                didDocument.comment = personName + " DID Document";
                didDocument.context = new List<string>() { jsonDoc["@context"].ToString() };

                didDocument.verificationMethod = new List<VerificationMethodMap>();
                VerificationMethodMap vmap = new VerificationMethodMap();
                foreach (var jsonNode in jsonDoc["verificationMethod"].AsArray())
                {
                    vmap = new VerificationMethodMap(
                        personName + " verificationMethod",
                        jsonNode["id"].ToString(), jsonNode["controller"].ToString(), jsonNode["type"].ToString(), null, null,
                        jsonNode["publicKeyBase58"].ToString(), jsonNode["privateKeyBase58"].ToString());
                    didDocument.verificationMethod.Add(vmap);
                }

                didDocument.keyAgreement = new List<VerificationMethodMap>();
                foreach (var jsonNode in jsonDoc["keyAgreement"].AsArray())
                {
                    vmap = new VerificationMethodMap(
                        personName + " keyAgreement",
                        jsonNode.ToString(), null, null, null, null, null, null);
                    didDocument.keyAgreement.Add(vmap);
                }

                didDocument.service = new List<ServiceMap>();
                ServiceMap smap = new ServiceMap(
                    personName + " Default serviceEndpoint",
                    didDocument.id + "#default",
                    new List<string>() { "default" },
                    new List<string>() { "http://" + host + ":" + port.ToString() + "/DIDCommEndpoint/" });
                didDocument.service.Add(smap);
                smap = new ServiceMap(
                    personName + " KnockKnock serviceEndpoint",
                    didDocument.id + "#doorknocker",
                    new List<string>() { "doorknocker" },
                    new List<string>() { "http://" + host + ":" + port.ToString() + "/DoorKnocker/" });
                didDocument.service.Add(smap);

                Console.WriteLine(personName + ": " + didDocument.ToString().Replace("\"type_\"", "\"type\""));

                File.WriteAllText(keyFilename2, didDocument.ToString());
            }
            else
            {
                string didWebKeyJson = File.ReadAllText(keyFilename);
                didWebKey = JsonSerializer.Deserialize<JsonWebKey>(didWebKeyJson);

                string jsonDIDDocument = File.ReadAllText(keyFilename2);
                Console.WriteLine(personName + ": " + jsonDIDDocument);
                DIDDocument.TryParse(jsonDIDDocument, out didDocument);
            }

            {
                SecretKey.Kid = didWebKey.Kid;
                SecretKey.Kty = didWebKey.Kty;
                SecretKey.Crv = didWebKey.Crv;
                SecretKey.D = didWebKey.D;
            }
            {
                PublicKey.Kid = didWebKey.Kid;
                PublicKey.Kty = didWebKey.Kty;
                PublicKey.Crv = didWebKey.Crv;
                PublicKey.X = didWebKey.X;
            }
            KeyId = didWebKey.Kid;
            ProofKey = Oberon.CreateKey(new CreateOberonKeyRequest());

            return didDocument;
        }
    }
}
