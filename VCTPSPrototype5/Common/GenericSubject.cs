using System;
using System.IO;
using Okapi.Keys;
using Okapi.Keys.V1;
using System.Text.Json;
using Okapi.Security;
using Okapi.Security.V1;

namespace VCTPSCommon
{
    public class GenericSubject
    {
        private const string keyFilenameTemplate = "c:\\temp\\{0}.keyfile.json";

        public bool IsInitialized = false;
        public JsonWebKey SecretKey = new JsonWebKey();
        public JsonWebKey PublicKey = new JsonWebKey();
        public string KeyId;
        public string Name;
        public string OrgName = "";
        public CreateOberonKeyResponse ProofKey;
        public string KeyFilename;

        public GenericSubject(string name)
        {
            Initialize(name);
        }

        public void Initialize(string name)
        {
            if (IsInitialized) return;
            IsInitialized = true;

            Name = name;
            KeyFilename = String.Format(keyFilenameTemplate, name);

            JsonWebKey didWebKey;
            if (!File.Exists(KeyFilename))
            {
                GenerateKeyResponse didKey = DIDKey.Generate(new GenerateKeyRequest { KeyType = KeyType.X25519 });
                didWebKey = didKey.Key[0];
                string didKeyJson = JsonSerializer.Serialize(didWebKey);
                File.WriteAllText(KeyFilename, didKeyJson);
            }
            else
            {
                string didKeyJson = File.ReadAllText(KeyFilename);
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
