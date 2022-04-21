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
    public static class WaybillFactory
    {
        public static string UBLWaybillType = "BTT.Waybill";
         
        public static Cac_Waybill NewWaybillClaims(
            string shippingorderUdid, string carrierpartyUdid, string freightforwarderUdid, string shipmentUdid
        )
        {
            string cbc_ID = Guid.NewGuid().ToString();
            string cbc_UBLVersionID = UBL22Helpers.UBLVERSIONID;

            Cac_Waybill claims = new Cac_Waybill(cbc_UBLVersionID, cbc_ID,
                Guid.NewGuid().ToString(), cbc_ID,
                DateTime.UtcNow,
                "Waybill 1234", new List<string> { "Waybill 1234" }, new List<string> { "abcd" },
                shippingorderUdid, "1.00",
                new List<string> { "abcd" },
                carrierpartyUdid, freightforwarderUdid, shipmentUdid
            );
            return claims;
        }

        public static BTT_Waybill_SealedEnvelope NewWaybillCredential(string udid, VCTPS_VCA_SealedEnvelope vca, Cac_Waybill claims, ByteString proofSk, string nonce64)
        {
            BTT_Waybill_EnvelopeContent content = new BTT_Waybill_EnvelopeContent(udid, BTTGenericCredential.DefaultContext, udid, claims, null);
            List<string> types = new List<string>(BTTGenericCredential.RootType);
            types.Add(UBLWaybillType);
            string vca64 = Helpers.ToBase64String(vca.ToString());
            BTTGenericCredential_PackingLabel label = new BTTGenericCredential_PackingLabel(types,
                BTTGenericCredentialType.UBLDocument, 0, BTTTrustLevel.OberonProof, BTTEncryptionFlag.NotEncrypted, null, "Waybill " + udid, new List<string> { "Waybill " + udid }, vca64);
            BTT_Waybill_Envelope envelope = new BTT_Waybill_Envelope(udid, label, content);
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            string hashproof64 = ProofHelpers.ComputeHashProof(hash64, proofSk, nonce64);
            BTTGenericCredential_EnvelopeSeal proof = new BTTGenericCredential_EnvelopeSeal(hash64, hashproof64);
            BTT_Waybill_SealedEnvelope credential = new BTT_Waybill_SealedEnvelope(envelope, proof);

            return credential;
       }
    }
}
