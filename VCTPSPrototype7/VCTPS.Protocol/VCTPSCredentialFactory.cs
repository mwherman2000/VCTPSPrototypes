using Google.Protobuf;
using Okapi.Keys;
using Okapi.Keys.V1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using VCTPS.Common;

namespace VCTPS.Protocol
{
    public static class VCTPSCredentialFactory
    {
        public static VCTPS_VCA_SealedEnvelope NewVCACredential(string grantedkey, string vckid, List<string> rights, List<string> restrictions, List<string> processing, ByteString proofSk, string nonce64)
        {
            JsonWebKey vcaWebKey;
            GenerateKeyResponse didKey = DIDKey.Generate(new GenerateKeyRequest { KeyType = KeyType.X25519 });
            vcaWebKey = didKey.Key[0];
            string vcakey = vcaWebKey.Kid;

            VCTPS_VCA_Caveat caveat = new VCTPS_VCA_Caveat(vcakey, rights, restrictions, processing);
            VCTPS_VCA_Claims claims = new VCTPS_VCA_Claims(VCTPS_VCA_Types.Proclamation.ToString(), null, vckid, grantedkey, caveat);
            VCTPS_VCA_EnvelopeContent content = new VCTPS_VCA_EnvelopeContent(vcakey, BTTGenericCredential.DefaultContext, vcakey, claims, null);
            List<string> types = new List<string>(BTTGenericCredential.RootType);
            types.Add(BTTGenericCredential.DefaultVCAType);
            BTTGenericCredential_PackingLabel label = new BTTGenericCredential_PackingLabel(types, BTTGenericCredentialType.VerifiableCapabilityAuthorization, 0, BTTTrustLevel.OberonProof, BTTEncryptionFlag.NotEncrypted, null, "VCA " + vcakey, new List<string> { "VCA " + vcakey }, "" );
            VCTPS_VCA_Envelope envelope = new VCTPS_VCA_Envelope(vcakey, label, content);
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            string hashproof64 = ProofHelpers.ComputeHashProof(hash64, proofSk, nonce64);
            BTTGenericCredential_EnvelopeSeal proof = new BTTGenericCredential_EnvelopeSeal(hash64, hashproof64);
            VCTPS_VCA_SealedEnvelope sealedEnvelope = new VCTPS_VCA_SealedEnvelope(envelope, proof);

            //ComputeBenchmark(json, proofSk, nonce64);
            //string vcJson = Helpers.GetTemplate("VCTPSPrototype5.vc2.json");
            //ComputeBenchmark(vcJson, proofSk, nonce64);

            return sealedEnvelope;

        }

        public static bool VerifyVCACredential(VCTPS_VCA_SealedEnvelope sealedEnvelope, ByteString proofPk, string nonce64)
        {
            bool valid = false;

            VCTPS_VCA_Envelope envelope = sealedEnvelope.envelope;
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            if (hash64 == sealedEnvelope.proof.hashedThumbprint64) // verify againt the Oberon hash proof
            {
                valid = ProofHelpers.VerifyHashProof(sealedEnvelope.proof.hashedThumbprint64, sealedEnvelope.proof.proof64, proofPk, nonce64);
            }

            return valid;
        }

        public static VCTPS_VCAACK_SealedEnvelope NewVCAACKCredential(string acknowledgementkey, string vckid, string vca64, ByteString proofSk, string nonce64)
        {
            JsonWebKey vcaWebKey;
            GenerateKeyResponse didKey = DIDKey.Generate(new GenerateKeyRequest { KeyType = KeyType.X25519 });
            vcaWebKey = didKey.Key[0];
            string vcakey = vcaWebKey.Kid;

            VCTPS_VCAACK_Acknowledgement ack = new VCTPS_VCAACK_Acknowledgement(vcakey, VCTPS_VCAACK_Determination.accepted.ToString(), vca64);
            VCTPS_VCAACK_Claims claims = new VCTPS_VCAACK_Claims(VCTPS_VCA_Types.Proclamation.ToString(), null, vckid, acknowledgementkey, ack);
            VCTPS_VCAACK_EnvelopeContent content = new VCTPS_VCAACK_EnvelopeContent(vcakey, BTTGenericCredential.DefaultContext, vcakey, claims, null);
            List<string> types = new List<string>(BTTGenericCredential.RootType);
            types.Add(BTTGenericCredential.DefaultVCAType);
            BTTGenericCredential_PackingLabel label = new BTTGenericCredential_PackingLabel(types, BTTGenericCredentialType.VerifiableCapabilityAuthorizationAcknowledgement, 0, BTTTrustLevel.OberonProof, BTTEncryptionFlag.NotEncrypted, null, "VCA " + vcakey, new List<string> { "VCA " + vcakey }, "");
            VCTPS_VCAACK_Envelope envelope = new VCTPS_VCAACK_Envelope(vcakey, label, content);
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            string hashproof64 = ProofHelpers.ComputeHashProof(hash64, proofSk, nonce64);
            BTTGenericCredential_EnvelopeSeal proof = new BTTGenericCredential_EnvelopeSeal(hash64, hashproof64);
            VCTPS_VCAACK_SealedEnvelope sealedEnvelope = new VCTPS_VCAACK_SealedEnvelope(envelope, proof);

            return sealedEnvelope;

        }

        public static bool VerifyVCAACKCredential(VCTPS_VCAACK_SealedEnvelope sealedEnvelope, ByteString proofPk, string nonce64)
        {
            bool valid = false;

            VCTPS_VCAACK_Envelope envelope = sealedEnvelope.envelope;
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            if (hash64 == sealedEnvelope.proof.hashedThumbprint64) // verify againt the Oberon hash proof
            {
                valid = ProofHelpers.VerifyHashProof(sealedEnvelope.proof.hashedThumbprint64, sealedEnvelope.proof.proof64, proofPk, nonce64);
            }

            return valid;
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
                string jsonproof64 = ProofHelpers.ComputeHashProof(json64, proofSk, nonce64);
            }
            stopwatch2.Stop();
            long jsonprooftime = stopwatch2.ElapsedMilliseconds;
            Console.WriteLine("jsonprooftime:\t" + jsonprooftime.ToString() + "ms");

            string hash364 = SHA256Helpers.ComputeHash(json);
            Stopwatch stopwatch3 = Stopwatch.StartNew();
            for (int i = 0; i < MAXTIMES; i++)
            {
                string hashproof64 = ProofHelpers.ComputeHashProof(hash364, proofSk, nonce64);
            }
            stopwatch3.Stop();
            long hashprooftime = stopwatch3.ElapsedMilliseconds;
            Console.WriteLine("hashprooftime:\t" + hashprooftime.ToString() + "ms");

            double reduction = 100.0 * (double)(jsonprooftime - hashprooftime) / (double)jsonprooftime;
            Console.WriteLine("reduction:\t" + reduction.ToString() + "%");
        }
    }
}
