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
    public static class ShipmentFactory
    {
        public static string UBLShipmentType = "BTT.Shipment";
         
        public static Cac_Shipment NewShipmentClaims(
            List<string> items, Cac_Address returnaddress, Cac_Address originaddress
        )
        {
            string cbc_ID = Guid.NewGuid().ToString();

            Cac_Shipment claims = new Cac_Shipment(cbc_ID, 
                new List<string> { "abcd" }, new List<string> { "abcd" },
                "0.0", "1",
                new List<string> { "abcd" }, new List<string> { "abcd" },
                items,
                returnaddress, originaddress
            );
            return claims;
        }

        public static BTT_Shipment_SealedEnvelope NewShipmentCredential(string udid, VCTPS_VCA_SealedEnvelope vca, Cac_Shipment claims, ByteString proofSk, string nonce64)
        {
            BTT_Shipment_EnvelopeContent content = new BTT_Shipment_EnvelopeContent(udid, BTTGenericCredential.DefaultContext, udid, claims, null);
            List<string> types = new List<string>(BTTGenericCredential.RootType);
            types.Add(UBLShipmentType);
            string vca64 = Helpers.ToBase64String(vca.ToString());
            BTTGenericCredential_PackingLabel label = new BTTGenericCredential_PackingLabel(types,
                BTTGenericCredentialType.UBLDocument, 0, BTTTrustLevel.OberonProof, BTTEncryptionFlag.NotEncrypted, null, "Shipment " + udid, new List<string> { "Shipment " + udid }, vca64);
            BTT_Shipment_Envelope envelope = new BTT_Shipment_Envelope(udid, label, content);
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            string hashproof64 = ProofHelpers.ComputeHashProof(hash64, proofSk, nonce64);
            BTTGenericCredential_EnvelopeSeal proof = new BTTGenericCredential_EnvelopeSeal(hash64, hashproof64);
            BTT_Shipment_SealedEnvelope credential = new BTT_Shipment_SealedEnvelope(envelope, proof);

            return credential;
       }
    }
}
