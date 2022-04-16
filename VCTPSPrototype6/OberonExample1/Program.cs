using System;
using Google.Protobuf;
using Okapi.Security;
using Okapi.Security.V1;
using System.Linq;

namespace OberonExample1
{
    public class Program
    {
        static void Main(string[] args)
        {
            // Originally from: https://github.com/trinsic-id/okapi/blob/main/dotnet/Tests/Okapi.Tests/OberonTests.cs#L14

            var key = Oberon.CreateKey(new CreateOberonKeyRequest());

            var json = ByteString.CopyFromUtf8("{{ \"text\": \"somejson\" }}");
            var nonce = ByteString.CopyFromUtf8("1234");

            // Alice - using Alice's Secret Key
            var token = Oberon.CreateToken(new CreateOberonTokenRequest
            {
                Data = json,
                Sk = key.Sk
            });

            CreateOberonProofResponse proof = Oberon.CreateProof(new CreateOberonProofRequest
            {
                Data = json,
                Nonce = nonce,
                Token = token.Token
            });

            // Bob - using Alice's Public Key
            var result1 = Oberon.VerifyProof(new VerifyOberonProofRequest
            {
                Data = json,
                Nonce = nonce,
                Pk = key.Pk,
                Proof = proof.Proof
            });
            Console.WriteLine("result1: " + result1.Valid.ToString());

            // Bob - using Alice's Public Key against a Base64 encoded proof
            string proof64 = proof.Proof.ToBase64();
            var result2 = Oberon.VerifyProof(new VerifyOberonProofRequest
            {
                Data = json,
                Nonce = nonce,
                Pk = key.Pk,
                Proof = ByteString.FromBase64(proof64)
            });
            Console.WriteLine("result2: " + result2.Valid.ToString());

            Console.WriteLine("Press Enter to exit...");
            Console.ReadLine();
        }
    }
}