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
    public static class DeliveryReceiptFactory
    {
        public static string UBLDeliveryReceiptType = "BTT.DeliveryReceipt";
         
        public static Cac_TransportEvent NewDeliveryReceiptClaims(
            List<string> decription,
            string shipmentUdid,
            string locationUdid,
            Cac_Contact contact
        )
        {
            string cbc_ID = Guid.NewGuid().ToString();
            string cbc_UBLVersionID = UBL22Helpers.UBLVERSIONID;
            Cac_Status status = new Cac_Status("1234", DateTime.UtcNow, DateTime.UtcNow, 
                new List<string> { "Status 1234" }, "1234", 
                new List<string> { "1234" }, "1", 
                new List<string> { "abcd" }, 
                "1234", "0", "0");
            Cac_Period period = new Cac_Period(DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow, "1234", 
                new List<string> { "1234" }, new List<string> { "abcd" } );   

            Cac_TransportEvent claims = new Cac_TransportEvent(
                cbc_ID, DateTime.UtcNow, DateTime.UtcNow, "1234", decription,
                cbc_UBLVersionID, shipmentUdid, 
                new List<Cac_Status>() { status }, 
                new List<Cac_Contact>() {  contact }, 
                locationUdid, new List<Cac_Period> { period });

            return claims;
        }

        public static BTT_DeliveryReceipt_SealedEnvelope NewDeliveryReceiptCredential(string udid, VCTPS_VCA_SealedEnvelope vca, Cac_TransportEvent claims, ByteString proofSk, string nonce64)
        {
            BTT_DeliveryReceipt_EnvelopeContent content = new BTT_DeliveryReceipt_EnvelopeContent(udid, BTTGenericCredential.DefaultContext, udid, claims, null);
            List<string> types = new List<string>(BTTGenericCredential.RootType);
            types.Add(UBLDeliveryReceiptType);
            string vca64 = Helpers.ToBase64String(vca.ToString());
            BTTGenericCredential_PackingLabel label = new BTTGenericCredential_PackingLabel(types,
                BTTGenericCredentialType.UBLDocument, 0, BTTTrustLevel.OberonProof, BTTEncryptionFlag.NotEncrypted, null, "DeliveryReceipt " + udid, new List<string> { "DeliveryReceipt " + udid }, vca64);
            BTT_DeliveryReceipt_Envelope envelope = new BTT_DeliveryReceipt_Envelope(udid, label, content);
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            string hashproof64 = ProofHelpers.ComputeHashProof(hash64, proofSk, nonce64);
            BTTGenericCredential_EnvelopeSeal proof = new BTTGenericCredential_EnvelopeSeal(hash64, hashproof64);
            BTT_DeliveryReceipt_SealedEnvelope credential = new BTT_DeliveryReceipt_SealedEnvelope(envelope, proof);

            return credential;
       }
    }
}
