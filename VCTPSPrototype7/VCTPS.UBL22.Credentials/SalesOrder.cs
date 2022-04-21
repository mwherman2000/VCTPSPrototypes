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
    public static class SalesOrderFactory
    {
        public static string UBLSalesOrderType = "BTT.SalesOrder";
         
        public static Cac_SalesOrder NewSalesOrderClaims(
            string supplierpartyUdid, string customerpartyUdid, string payeepartyUdid, List<string> invoicelineUdids
        )
        {
            string cbc_ID = Guid.NewGuid().ToString();
            string cbc_UBLVersionID = UBL22Helpers.UBLVERSIONID;
            Cac_MonetaryTotal total = new Cac_MonetaryTotal("1.00", "1.00", "1.00", "1.00", "1.00", "1.00", "1.00", "1.00", "1.00");

            Cac_SalesOrder claims = new Cac_SalesOrder(cbc_ID, cbc_UBLVersionID, 
                DateTime.UtcNow, 
                new List<string> { "abcd" },
                supplierpartyUdid, customerpartyUdid, payeepartyUdid,
                total, invoicelineUdids
            );
            return claims;
        }

        public static BTT_SalesOrder_SealedEnvelope NewSalesOrderCredential(string udid, VCTPS_VCA_SealedEnvelope vca, Cac_SalesOrder claims, ByteString proofSk, string nonce64)
        {
            BTT_SalesOrder_EnvelopeContent content = new BTT_SalesOrder_EnvelopeContent(udid, BTTGenericCredential.DefaultContext, udid, claims, null);
            List<string> types = new List<string>(BTTGenericCredential.RootType);
            types.Add(UBLSalesOrderType);
            string vca64 = Helpers.ToBase64String(vca.ToString());
            BTTGenericCredential_PackingLabel label = new BTTGenericCredential_PackingLabel(types,
                BTTGenericCredentialType.UBLDocument, 0, BTTTrustLevel.OberonProof, BTTEncryptionFlag.NotEncrypted, null, "SalesOrder " + udid, new List<string> { "SalesOrder " + udid }, vca64);
            BTT_SalesOrder_Envelope envelope = new BTT_SalesOrder_Envelope(udid, label, content);
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            string hashproof64 = ProofHelpers.ComputeHashProof(hash64, proofSk, nonce64);
            BTTGenericCredential_EnvelopeSeal proof = new BTTGenericCredential_EnvelopeSeal(hash64, hashproof64);
            BTT_SalesOrder_SealedEnvelope credential = new BTT_SalesOrder_SealedEnvelope(envelope, proof);

            return credential;
       }
    }
}
