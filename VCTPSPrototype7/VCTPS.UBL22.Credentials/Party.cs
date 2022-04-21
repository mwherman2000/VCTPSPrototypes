using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Google.Protobuf;
using VCTPS.Common;
using VCTPS.Protocol;
using VCTPS.UBL22.Common;

namespace VCTPS.UBL22.Credentials
{
    public static class PartyFactory
    {
        public static string UBLPartyType = "BTT.Party";

        public static Cac_Party NewPartyClaims(
            string partyname, Cac_Address address, Cac_Contact contact, string personUdid
        )
        { 
            Cac_Party claims = new Cac_Party("1234", "1234", "http://example.com", "1234", "1234", "1234", 
                new List<string> { "abcd" },
                new List<string> { partyname }, address, contact, new List<string> { personUdid } 
            );
            return claims;
        }

        public static BTT_Party_SealedEnvelope NewPartyCredential(string udid, VCTPS_VCA_SealedEnvelope vca, Cac_Party claims, ByteString proofSk, string nonce64)
        {
            BTT_Party_EnvelopeContent content = new BTT_Party_EnvelopeContent(udid, BTTGenericCredential.DefaultContext, udid, claims, null);
            List<string> types = new List<string>(BTTGenericCredential.RootType);
            types.Add(UBLPartyType);
            string vca64 = Helpers.ToBase64String(vca.ToString());
            BTTGenericCredential_PackingLabel label = new BTTGenericCredential_PackingLabel(types,
                BTTGenericCredentialType.UBLDocument, 0, BTTTrustLevel.OberonProof, BTTEncryptionFlag.NotEncrypted, null, "Party " + udid, new List<string> { "Party " + udid }, vca64);
            BTT_Party_Envelope envelope = new BTT_Party_Envelope(udid, label, content);
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            string hashproof64 = ProofHelpers.ComputeHashProof(hash64, proofSk, nonce64);
            BTTGenericCredential_EnvelopeSeal proof = new BTTGenericCredential_EnvelopeSeal(hash64, hashproof64);
            BTT_Party_SealedEnvelope credential = new BTT_Party_SealedEnvelope(envelope, proof);

            return credential;
       }
    }
}
