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
    public static class InvoiceFactory
    {
        public static string UBLInvoiceType = "BTT.Invoice";
         
        public static Cac_Invoice NewInvoiceClaims(
            string orderUdid, string supplypartyUdid, string customerpartyUdid, string payeepartyUdid, List<string> invoicelineUdids
        )
        {
            string cbc_ID = Guid.NewGuid().ToString();
            Cac_Period period = new Cac_Period(DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow, "1234",
                new List<string> { "1234" }, new List<string> { "abcd" });
            Cac_MonetaryTotal total = new Cac_MonetaryTotal("1.00", "1.00", "1.00", "1.00", "1.00", "1.00", "1.00", "1.00", "1.00");

            Cac_Invoice claims = new Cac_Invoice(cbc_ID, cbc_ID,
                DateTime.UtcNow, DateTime.UtcNow, 
                new List<string> { "abcd" },
                new List<Cac_Period> { period }, orderUdid, supplypartyUdid, customerpartyUdid, payeepartyUdid,
                total,
                invoicelineUdids
            );
            return claims;
        }

        public static BTT_Invoice_SealedEnvelope NewInvoiceCredential(string udid, VCTPS_VCA_SealedEnvelope vca, Cac_Invoice claims, ByteString proofSk, string nonce64)
        {
            BTT_Invoice_EnvelopeContent content = new BTT_Invoice_EnvelopeContent(udid, BTTGenericCredential.DefaultContext, udid, claims, null);
            List<string> types = new List<string>(BTTGenericCredential.RootType);
            types.Add(UBLInvoiceType);
            string vca64 = Helpers.ToBase64String(vca.ToString());
            BTTGenericCredential_PackingLabel label = new BTTGenericCredential_PackingLabel(types,
                BTTGenericCredentialType.UBLDocument, 0, BTTTrustLevel.OberonProof, BTTEncryptionFlag.NotEncrypted, null, "Invoice " + udid, new List<string> { "Invoice " + udid }, vca64);
            BTT_Invoice_Envelope envelope = new BTT_Invoice_Envelope(udid, label, content);
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            string hashproof64 = ProofHelpers.ComputeHashProof(hash64, proofSk, nonce64);
            BTTGenericCredential_EnvelopeSeal proof = new BTTGenericCredential_EnvelopeSeal(hash64, hashproof64);
            BTT_Invoice_SealedEnvelope credential = new BTT_Invoice_SealedEnvelope(envelope, proof);

            return credential;
       }
    }
}
