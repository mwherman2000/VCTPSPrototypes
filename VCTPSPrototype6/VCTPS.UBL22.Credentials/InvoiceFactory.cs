using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Google.Protobuf;
using VCTPS.Common;
using VCTPS.Protocol;
using VCTPS.UBL22.Common;
using VCTPS.UBL22.Invoice;

namespace VCTPS.UBL22.Credentials
{
    public static class InvoiceFactory
    {
        public static string UBLInvoiceType = "UBL22.Invoice";
         
        public static Cac_Invoice NewInvoiceClaims(
            DateTime cbc_IssueDate,
            Cbc_ListCode cbc_InvoiceTypeCode,
            Cbc_Note cbc_Note,

            DateTime cbc_TaxPointDate,
            Cbc_ListCode cbc_DocumentCurrencyCode,
            string cbc_AccountingCost,
            Cbc_TimePeriod cbc_InvoicePeriod,
            Cbc_OrderReference cbc_OrderReference,

            Cac_DocumentReference cac_ContractDocumentReference,
            List<Cac_DocumentReference> cac_AdditionalDocumentReferences,

            Cac_SupplierParty cac_AccountingSupplierParty,
            Cac_CustomerParty cac_AccountingCustomerParty,
            Cac_Party cac_PayeeParty,

            Cac_Delivery cac_Delivery,

            Cac_PaymentMeans cac_PaymentMeans,
            Cac_PaymentTerms cac_PaymentTerms,
            List<Cac_AllowanceCharge> cac_AllowanceCharges,
            Cac_TaxTotal cac_TaxTotal,
            Cac_MonetaryTotal cac_LegalMonetaryTotal,
            List<string> cac_InvoiceLineUdid
        )
        {
            string cbc_UBLVersionID = UBL22Helpers.UBLVERSIONID;
            string cbc_ID = Guid.NewGuid().ToString();

            Cac_Invoice claims = new Cac_Invoice(
                cbc_UBLVersionID, 
                cbc_ID,
                cbc_IssueDate,
                cbc_InvoiceTypeCode,
                cbc_Note,

                cbc_TaxPointDate,
                cbc_DocumentCurrencyCode,
                cbc_AccountingCost,
                cbc_InvoicePeriod,
                cbc_OrderReference,

                cac_ContractDocumentReference,
                cac_AdditionalDocumentReferences,

                cac_AccountingSupplierParty,
                cac_AccountingCustomerParty,
                cac_PayeeParty,

                cac_Delivery,

                cac_PaymentMeans,
                cac_PaymentTerms,
                cac_AllowanceCharges,
                cac_TaxTotal,
                cac_LegalMonetaryTotal,
                cac_InvoiceLine
            );
            return claims;
        }

        public static UBL22_Invoice_SealedEnvelope NewInvoiceCredential(string udid, VCTPS_VCA_SealedEnvelope vca, Cac_Invoice claims, ByteString proofSk, string nonce64)
        {
            UBL22_Invoice_EnvelopeContent content = new UBL22_Invoice_EnvelopeContent(udid, BTTGenericCredential.DefaultContext, udid, claims, null);
            List<string> types = new List<string>(BTTGenericCredential.RootType);
            types.Add(UBLInvoiceType);
            string vca64 = Helpers.ToBase64String(vca.ToString());
            BTTGenericCredential_PackingLabel label = new BTTGenericCredential_PackingLabel(types,
                BTTGenericCredentialType.UBLDocument, 0, BTTTrustLevel.OberonProof, BTTEncryptionFlag.NotEncrypted, null, "Invoice " + udid, new List<string> { "Invoice " + udid }, vca64);
            UBL22_Invoice_Envelope envelope = new UBL22_Invoice_Envelope(udid, label, content);
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            string hashproof64 = ProofHelpers.ComputeHashProof(hash64, proofSk, nonce64);
            BTTGenericCredential_EnvelopeSeal proof = new BTTGenericCredential_EnvelopeSeal(hash64, hashproof64);
            UBL22_Invoice_SealedEnvelope invoice = new UBL22_Invoice_SealedEnvelope(envelope, proof);

            return invoice;
       }
    }
}
