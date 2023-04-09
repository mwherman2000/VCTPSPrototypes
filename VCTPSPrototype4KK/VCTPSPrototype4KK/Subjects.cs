using System;
using System.IO;
using Okapi.Keys;
using Okapi.Keys.V1;
using System.Text.Json;
using Okapi.Security;
using Okapi.Security.V1;
using VCTPSPrototype4KK;

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
        public static void Initialize(string host, int port)
        {
            if (IsInitialized) return;
            IsInitialized = true;

            JsonWebKey didWebKey;
            if (true) // !File.Exists(keyFilename))
            {
                GenerateKeyResponse didKey = DIDKey.Generate(new GenerateKeyRequest { KeyType = KeyType.X25519 });
                didWebKey = didKey.Key[0];
                string didKeyJson = JsonSerializer.Serialize(didWebKey);
                File.WriteAllText(keyFilename, didKeyJson);

                var didDoc = didKey.DidDocument;
                Console.WriteLine("Charlie: " + didDoc);
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
                didDocument.id = didKey.Key[0].Kid;
                didDocument.context = new List<string>() { "https://www.w3.org/ns/did/v1" };
                ServiceMap smap = new ServiceMap(didKey.Key[0].Kid + "#default",
                    new List<string>() { "default" },
                    new List<string>() { "http://"+ host + ":" + port.ToString() + "/DIDCommEndpoint/" });
                didDocument.service = new List<ServiceMap>() { smap };
                didDocument.verificationMethod = new List<VerificationMethodMap>() { /* TODO */ };
                didDocument.keyAgreement = new List<VerificationMethodMap>() { /* TODO */ };
                Console.WriteLine("Charlie: " + didDocument);
            }
            else
            {
                string didKeyJson = File.ReadAllText(keyFilename);
                didWebKey = JsonSerializer.Deserialize<JsonWebKey>(didKeyJson);
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
        public static void Initialize(string host, int port)
        {
            if (IsInitialized) return;
            IsInitialized = true;

            JsonWebKey didWebKey;
            if (!File.Exists(keyFilename))
            {
                GenerateKeyResponse didKey = DIDKey.Generate(new GenerateKeyRequest { KeyType = KeyType.X25519 });
                didWebKey = didKey.Key[0];
                string didKeyJson = JsonSerializer.Serialize(didWebKey);
                File.WriteAllText(keyFilename, didKeyJson);
            }
            else
            {
                string didKeyJson = File.ReadAllText(keyFilename);
                didWebKey = JsonSerializer.Deserialize<JsonWebKey>(didKeyJson);
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
        public static void Initialize(string host, int port)
        {
            if (IsInitialized) return;
            IsInitialized = true;

            JsonWebKey didWebKey;
            if (!File.Exists(keyFilename))
            {
                GenerateKeyResponse didKey = DIDKey.Generate(new GenerateKeyRequest { KeyType = KeyType.X25519 });
                didWebKey = didKey.Key[0];
                string didKeyJson = JsonSerializer.Serialize(didWebKey);
                File.WriteAllText(keyFilename, didKeyJson);
            }
            else
            {
                string didKeyJson = File.ReadAllText(keyFilename);
                didWebKey = JsonSerializer.Deserialize<JsonWebKey>(didKeyJson);
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
