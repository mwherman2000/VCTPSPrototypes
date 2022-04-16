using Okapi.Transport;
using Okapi.Transport.V1;
using Pbmse.V1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Okapi.Security.V1;
using Okapi.Security;
using System.Reflection;
using Google.Protobuf;

namespace VCTPS.Common
{
    public static class Helpers
    {
        public static string GetTemplate(Assembly assembly, string resname)
        {
            var streams = assembly.GetManifestResourceNames();
            var nfeJsonEnvelopeStream = assembly.GetManifestResourceStream(resname);
            if (nfeJsonEnvelopeStream == null) return "";
            byte[] res = new byte[nfeJsonEnvelopeStream.Length];
            int nBytes = nfeJsonEnvelopeStream.Read(res);
            string template = Encoding.UTF8.GetString(res);

            return template;
        }

        // https://docs.microsoft.com/en-us/dotnet/api/system.convert.tobase64string?view=net-5.0#System_Convert_ToBase64String_System_Byte___
        public static string ToBase64String(string s)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(s);
            string s64 = Convert.ToBase64String(bytes);
            return s64;
        }
        public static string ToBase64String(byte[] bytes)
        {
            string s64 = Convert.ToBase64String(bytes);
            return s64;
        }
        public static byte[] FromBase64String(string s)
        {
            byte[] bytes = Convert.FromBase64String(s);
            return bytes;
        }
    }

    static public class SHA256Helpers
    {
        static private SHA256 HashProvider = SHA256.Create();

        // https://docs.microsoft.com/en-us/dotnet/standard/security/ensuring-data-integrity-with-hash-codes
        public static byte[] ComputeHash(byte[] bytes)
        {
            byte[] hash;

            hash = HashProvider.ComputeHash(bytes);

            return hash;
        }

        public static string ComputeHash(string plaintext)
        {
            string hash64;
            byte[] hash;

            byte[] bytes = Encoding.UTF8.GetBytes(plaintext);
            hash = HashProvider.ComputeHash(bytes);
            hash64 = Helpers.ToBase64String(hash);

            return hash64;
        }

        public static byte[] ComputeFileHash(string inFile)
        {
            byte[] hashedValue;

            byte[] fileBytes = File.ReadAllBytes(inFile);

            hashedValue = ComputeHash(fileBytes);

            return hashedValue;
        }
    }

    public static class ProofHelpers
    {
        public static string ComputeHashProof(string hash64, ByteString proofSk, string nonce64)
        {
            ByteString data = ByteString.FromBase64(hash64);
            var token = Oberon.CreateToken(new CreateOberonTokenRequest
            {
                Data = data,
                Sk = proofSk
            });

            ByteString nonce = ByteString.FromBase64(nonce64);
            CreateOberonProofResponse proof = Oberon.CreateProof(new CreateOberonProofRequest
            {
                Data = data,
                Nonce = nonce,
                Token = token.Token
            });

            string proof64 = proof.Proof.ToBase64();
            return proof64;
        }

        public static bool VerifyHashProof(string hash64, string proof64, ByteString proofPk, string nonce64)
        {
            bool valid = false;

            ByteString nonce = ByteString.FromBase64(nonce64);
            ByteString hash = ByteString.FromBase64(nonce64);
            var result = Oberon.VerifyProof(new VerifyOberonProofRequest
            {
                Data = hash,
                Nonce = nonce,
                Pk = proofPk,
                Proof = ByteString.FromBase64(proof64)
            });

            valid = result.Valid;

            return valid;
        }
    }
}
