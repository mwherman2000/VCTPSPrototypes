using System;
using System.IO;
using Okapi.Keys;
using Okapi.Keys.V1;
using System.Text.Json;
using Okapi.Security;
using Okapi.Security.V1;
using VCTPSPrototype4KK;
using System.Text.Json.Nodes;
using Google.Protobuf.WellKnownTypes;
using System.Collections.Generic;

namespace Subjects
{
    public static class Charlie
    {
        public static bool IsInitialized = false;
        public static JsonWebKey SecretKey = new JsonWebKey();
        public static JsonWebKey PublicKey = new JsonWebKey();
        public static string KeyId;
        public static string Name = "Charlie";
        public static CreateOberonKeyResponse ProofKey;

        const string keyFilename = "c:\\temp\\Charlie.keyfile.json";
        const string keyFilename2 = "c:\\temp\\Charlie.keyfile2.json";

        public static void Initialize(string host, int port)
        {
            //File.Delete(keyFilename);
            //File.Delete(keyFilename2);

            if (IsInitialized) return;
            IsInitialized = true;

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
                Console.WriteLine("Charlie: " + jsonDoc.ToJsonString(options));
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

                DIDDocument didDocument = new DIDDocument();
                didDocument.id = jsonDoc["id"].ToString();
                didDocument.comment = Name + " DID Document";
                didDocument.context = new List<string>() { jsonDoc["@context"].ToString() };

                didDocument.verificationMethod = new List<VerificationMethodMap>();
                VerificationMethodMap vmap = new VerificationMethodMap();
                foreach (var jsonNode in jsonDoc["verificationMethod"].AsArray())
                {
                    vmap = new VerificationMethodMap(
                        Name + " verificationMethod",
                        jsonNode["id"].ToString(), jsonNode["controller"].ToString(), jsonNode["type"].ToString(), null, null, 
                        jsonNode["publicKeyBase58"].ToString(), jsonNode["privateKeyBase58"].ToString());
                    didDocument.verificationMethod.Add(vmap);
                }

                didDocument.keyAgreement = new List<VerificationMethodMap>();
                foreach (var jsonNode in jsonDoc["keyAgreement"].AsArray())
                {
                    vmap = new VerificationMethodMap(
                        Name + " keyAgreement",
                        jsonNode.ToString(), null, null, null, null, null, null);
                    didDocument.keyAgreement.Add(vmap);
                }

                didDocument.service = new List<ServiceMap>();
                ServiceMap smap = new ServiceMap(
                    Name + " Default serviceEndpoint",
                    didDocument.id + "#default",
                    new List<string>() { "default" },
                    new List<string>() { "http://" + host + ":" + port.ToString() + "/DIDCommEndpoint/" });
                didDocument.service.Add(smap);
                smap = new ServiceMap(
                    Name + " KnockKnock serviceEndpoint",
                    didDocument.id + "#doorknocker",
                    new List<string>() { "doorknocker" },
                    new List<string>() { "http://" + host + ":" + port.ToString() + "/DoorKnocker/" });
                didDocument.service.Add(smap);

                Console.WriteLine(Name + ": " + didDocument.ToString().Replace("\"type_\"", "\"type\""));

                File.WriteAllText(keyFilename2, didDocument.ToString());
            }
            else
            {
                string didWebKeyJson = File.ReadAllText(keyFilename);
                didWebKey = JsonSerializer.Deserialize<JsonWebKey>(didWebKeyJson);

                string jsonDIDDocument = File.ReadAllText(keyFilename2);
                Console.WriteLine("Charlie: " + jsonDIDDocument);
                DIDDocument didDocument = new DIDDocument();
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
        }
    }

    public static class Delta
    {
        public static bool IsInitialized = false;
        public static JsonWebKey SecretKey = new JsonWebKey();
        public static JsonWebKey PublicKey = new JsonWebKey();
        public static string KeyId;
        public static string Name = "Delta";
        public static CreateOberonKeyResponse ProofKey;

        const string keyFilename = "c:\\temp\\Delta.keyfile.json";
        const string keyFilename2 = "c:\\temp\\Delta.keyfile2.json";

        public static void Initialize(string host, int port)
        {
            //File.Delete(keyFilename);
            //File.Delete(keyFilename2);

            if (IsInitialized) return;
            IsInitialized = true;

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
                Console.WriteLine("Delta: " + jsonDoc.ToJsonString(options));
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

                DIDDocument didDocument = new DIDDocument();
                didDocument.id = jsonDoc["id"].ToString();
                didDocument.comment = Name + " DID Document";
                didDocument.context = new List<string>() { jsonDoc["@context"].ToString() };

                didDocument.verificationMethod = new List<VerificationMethodMap>();
                VerificationMethodMap vmap = new VerificationMethodMap();
                foreach (var jsonNode in jsonDoc["verificationMethod"].AsArray())
                {
                    vmap = new VerificationMethodMap(
                        Name + " verificationMethod",
                        jsonNode["id"].ToString(), jsonNode["controller"].ToString(), jsonNode["type"].ToString(), null, null,
                        jsonNode["publicKeyBase58"].ToString(), jsonNode["privateKeyBase58"].ToString());
                    didDocument.verificationMethod.Add(vmap);
                }

                didDocument.keyAgreement = new List<VerificationMethodMap>();
                foreach (var jsonNode in jsonDoc["keyAgreement"].AsArray())
                {
                    vmap = new VerificationMethodMap(
                        Name + " keyAgreement",
                        jsonNode.ToString(), null, null, null, null, null, null);
                    didDocument.keyAgreement.Add(vmap);
                }

                didDocument.service = new List<ServiceMap>();
                ServiceMap smap = new ServiceMap(
                    Name + " Default serviceEndpoint",
                    didDocument.id + "#default",
                    new List<string>() { "default" },
                    new List<string>() { "http://" + host + ":" + port.ToString() + "/DIDCommEndpoint/" });
                didDocument.service.Add(smap);
                smap = new ServiceMap(
                    Name + " KnockKnock serviceEndpoint",
                    didDocument.id + "#doorknocker",
                    new List<string>() { "doorknocker" },
                    new List<string>() { "http://" + host + ":" + port.ToString() + "/DoorKnocker/" });
                didDocument.service.Add(smap);

                Console.WriteLine(Name + ": " + didDocument.ToString().Replace("\"type_\"", "\"type\""));

                File.WriteAllText(keyFilename2, didDocument.ToString());
            }
            else
            {
                string didWebKeyJson = File.ReadAllText(keyFilename);
                didWebKey = JsonSerializer.Deserialize<JsonWebKey>(didWebKeyJson);

                string jsonDIDDocument = File.ReadAllText(keyFilename2);
                Console.WriteLine("Delta: " + jsonDIDDocument);
                DIDDocument didDocument = new DIDDocument();
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
        }
    }
    public static class Echo
    {
        public static bool IsInitialized = false;
        public static JsonWebKey SecretKey = new JsonWebKey();
        public static JsonWebKey PublicKey = new JsonWebKey();
        public static string KeyId;
        public static string Name = "Echo";
        public static CreateOberonKeyResponse ProofKey;

        const string keyFilename = "c:\\temp\\Echo.keyfile.json";
        const string keyFilename2 = "c:\\temp\\Echo.keyfile2.json";

        public static void Initialize(string host, int port)
        {
            //File.Delete(keyFilename);
            //File.Delete(keyFilename2);

            if (IsInitialized) return;
            IsInitialized = true;

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
                Console.WriteLine("Echo: " + jsonDoc.ToJsonString(options));
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

                DIDDocument didDocument = new DIDDocument();
                didDocument.id = jsonDoc["id"].ToString();
                didDocument.comment = Name + " DID Document";
                didDocument.context = new List<string>() { jsonDoc["@context"].ToString() };

                didDocument.verificationMethod = new List<VerificationMethodMap>();
                VerificationMethodMap vmap = new VerificationMethodMap();
                foreach (var jsonNode in jsonDoc["verificationMethod"].AsArray())
                {
                    vmap = new VerificationMethodMap(
                        Name + " verificationMethod",
                        jsonNode["id"].ToString(), jsonNode["controller"].ToString(), jsonNode["type"].ToString(), null, null,
                        jsonNode["publicKeyBase58"].ToString(), jsonNode["privateKeyBase58"].ToString());
                    didDocument.verificationMethod.Add(vmap);
                }

                didDocument.keyAgreement = new List<VerificationMethodMap>();
                foreach (var jsonNode in jsonDoc["keyAgreement"].AsArray())
                {
                    vmap = new VerificationMethodMap(
                        Name + " keyAgreement",
                        jsonNode.ToString(), null, null, null, null, null, null);
                    didDocument.keyAgreement.Add(vmap);
                }

                didDocument.service = new List<ServiceMap>();
                ServiceMap smap = new ServiceMap(
                    Name + " Default serviceEndpoint",
                    didDocument.id + "#default",
                    new List<string>() { "default" },
                    new List<string>() { "http://" + host + ":" + port.ToString() + "/DIDCommEndpoint/" });
                didDocument.service.Add(smap);
                smap = new ServiceMap(
                    Name + " KnockKnock serviceEndpoint",
                    didDocument.id + "#doorknocker",
                    new List<string>() { "doorknocker" },
                    new List<string>() { "http://" + host + ":" + port.ToString() + "/DoorKnocker/" });
                didDocument.service.Add(smap);

                Console.WriteLine(Name + ": " + didDocument.ToString().Replace("\"type_\"", "\"type\""));

                File.WriteAllText(keyFilename2, didDocument.ToString());
            }
            else
            {
                string didWebKeyJson = File.ReadAllText(keyFilename);
                didWebKey = JsonSerializer.Deserialize<JsonWebKey>(didWebKeyJson);

                string jsonDIDDocument = File.ReadAllText(keyFilename2);
                Console.WriteLine("Echo: " + jsonDIDDocument);
                DIDDocument didDocument = new DIDDocument();
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
        }
    }
}