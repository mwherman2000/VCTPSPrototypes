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
    public static class InvoiceLineFactory
    {
        public static string UBLInvoiceLineType = "BTT.InvoiceLine";
         
        public static Cac_InvoiceLine NewInvoiceLineClaims(
            string quantity, Cac_Item item, Cac_Price price
        )
        {
            string cbc_ID = Guid.NewGuid().ToString();

            Cac_InvoiceLine claims = new Cac_InvoiceLine(cbc_ID, cbc_ID,
                new List<string> { "abcd" },
                quantity, "0.0",
                DateTime.UtcNow, "1234", "1.00", "1234", "1234", item, price
            );
            return claims;
        }

        public static BTT_InvoiceLine_SealedEnvelope NewInvoiceLineCredential(string udid, VCTPS_VCA_SealedEnvelope vca, Cac_InvoiceLine claims, ByteString proofSk, string nonce64)
        {
            BTT_InvoiceLine_EnvelopeContent content = new BTT_InvoiceLine_EnvelopeContent(udid, BTTGenericCredential.DefaultContext, udid, claims, null);
            List<string> types = new List<string>(BTTGenericCredential.RootType);
            types.Add(UBLInvoiceLineType);
            string vca64 = Helpers.ToBase64String(vca.ToString());
            BTTGenericCredential_PackingLabel label = new BTTGenericCredential_PackingLabel(types,
                BTTGenericCredentialType.UBLDocument, 0, BTTTrustLevel.OberonProof, BTTEncryptionFlag.NotEncrypted, null, "InvoiceLine " + udid, new List<string> { "InvoiceLine " + udid }, vca64);
            BTT_InvoiceLine_Envelope envelope = new BTT_InvoiceLine_Envelope(udid, label, content);
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            string hashproof64 = ProofHelpers.ComputeHashProof(hash64, proofSk, nonce64);
            BTTGenericCredential_EnvelopeSeal proof = new BTTGenericCredential_EnvelopeSeal(hash64, hashproof64);
            BTT_InvoiceLine_SealedEnvelope credential = new BTT_InvoiceLine_SealedEnvelope(envelope, proof);

            return credential;
       }
    }
}
