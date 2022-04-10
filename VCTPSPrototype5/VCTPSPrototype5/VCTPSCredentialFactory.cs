using Google.Protobuf;
using Okapi.Keys;
using Okapi.Keys.V1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace VCTPSPrototype5
{
    public static class VCTPSCredentialFactory
    {
        public const string DefaultVCAType = "Verifiable Capability Authorization";

        public static VCTPS_VCA_SealedEnvelope NewVCACredential(string grantedkey, string vckid, string[] rights, string[] restrictions, string[] processing, ByteString proofSk, string nonce64)
        {
            JsonWebKey vcaWebKey;
            GenerateKeyResponse didKey = DIDKey.Generate(new GenerateKeyRequest { KeyType = KeyType.X25519 });
            vcaWebKey = didKey.Key[0];
            string vcakey = vcaWebKey.Kid;

            VCTPS_VCA_Caveat caveat = new VCTPS_VCA_Caveat(vcakey, rights.ToList<string>(), restrictions.ToList<string>(), processing.ToList<string>());
            VCTPS_VCA_Claims claims = new VCTPS_VCA_Claims(VCTPS_VCA_Types.Proclamation.ToString(), null, vckid, grantedkey, caveat);
            VCTPS_VCA_EnvelopeContent content = new VCTPS_VCA_EnvelopeContent(vcakey, BTTGenericCredential.DefaultContext, vcakey, claims, null);
            List<string> types = BTTGenericCredential.RootType;
            types.Add(DefaultVCAType);
            BTTGenericCredential_PackingLabel label = new BTTGenericCredential_PackingLabel(types, BTTGenericCredentialType.VerifiableCapabilityAuthorization, 0, BTTTrustLevel.OberonProof, BTTEncryptionFlag.NotEncrypted, null, "VCA " + vcakey, new List<string> { "VCA " + vcakey }, "" );
            VCTPS_VCA_Envelope envelope = new VCTPS_VCA_Envelope(vcakey, label, content);
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            string hashproof64 = ProofHelpers.ComputeProof(hash64, proofSk, nonce64);
            //ComputeBenchmark(json, proofSk, nonce64);
            BTTGenericCredential_EnvelopeSeal proof = new BTTGenericCredential_EnvelopeSeal(hash64, hashproof64);
            VCTPS_VCA_SealedEnvelope sealedEnvelope = new VCTPS_VCA_SealedEnvelope(envelope, proof);

            //string vcJson = Helpers.GetTemplate("VCTPSPrototype5.vc2.json");
            //ComputeBenchmark(vcJson, proofSk, nonce64);

            return sealedEnvelope;

        }

        private static void ComputeBenchmark(string json, ByteString proofSk, string nonce64)
        {
            int MAXTIMES = 10000;

            Console.WriteLine("json.length:\t" + json.Length + " bytes");
            Console.WriteLine("iterations:\t" + MAXTIMES);

            Stopwatch stopwatch1 = Stopwatch.StartNew();
            for (int i = 0; i < MAXTIMES; i++)
            {
                string hash64 = SHA256Helpers.ComputeHash(json);
            }
            stopwatch1.Stop();
            long hashtime = stopwatch1.ElapsedMilliseconds;
            Console.WriteLine("hashtime:\t" + hashtime.ToString() + "ms");

            string json64 = Helpers.ToBase64String(json);
            Stopwatch stopwatch2 = Stopwatch.StartNew();
            for (int i = 0; i < MAXTIMES; i++)
            {
                string jsonproof64 = ProofHelpers.ComputeProof(json64, proofSk, nonce64);
            }
            stopwatch2.Stop();
            long jsonprooftime = stopwatch2.ElapsedMilliseconds;
            Console.WriteLine("jsonprooftime:\t" + jsonprooftime.ToString() + "ms");

            string hash364 = SHA256Helpers.ComputeHash(json);
            Stopwatch stopwatch3 = Stopwatch.StartNew();
            for (int i = 0; i < MAXTIMES; i++)
            {
                string hashproof64 = ProofHelpers.ComputeProof(hash364, proofSk, nonce64);
            }
            stopwatch3.Stop();
            long hashprooftime = stopwatch3.ElapsedMilliseconds;
            Console.WriteLine("hashprooftime:\t" + hashprooftime.ToString() + "ms");

            double reduction = 100.0 * (double)(jsonprooftime - hashprooftime) / (double)jsonprooftime;
            Console.WriteLine("reduction:\t" + reduction.ToString() + "%");
        }
    }
}
