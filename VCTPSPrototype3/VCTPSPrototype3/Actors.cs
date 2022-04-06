using System;
using System.IO;
using Okapi.Keys;
using Okapi.Keys.V1;
using System.Text.Json;
using Okapi.Security;
using Okapi.Security.V1;

namespace Actors
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
        public static void Initialize()
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

    public static class Delta
    {
        public static bool IsInitialized = false;
        public static JsonWebKey SecretKey = new JsonWebKey();
        public static JsonWebKey PublicKey = new JsonWebKey();
        public static string KeyId;
        public static string Name = "Delta";
        public static CreateOberonKeyResponse ProofKey;

        const string keyFilename = "c:\\temp\\Delta.keyfile.json";
        public static void Initialize()
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
        public static void Initialize()
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
