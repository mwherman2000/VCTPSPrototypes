using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VCTPS.Common;
using Google.Protobuf;
using VCTPS.Protocol;

namespace VCTPS.UBL21Credentials
{
    public static class UBL21CredentialFactory
    {
        public static string UBLVERSIONID = "2.2";
        public static string UBLItemType = "UBL22Item";
        public static string UBLPartyType = "UBL22Party";
        public static string UBLInvoiceType = "UBL22Invoice2";

        public static Cac_Item_Claims NewItemClaims(
                string cbc_Name,
                Cac_SellersItemIdentification cac_SellersItemIdentification,
                Cbc_SchemeCode cac_StandardItemIdentification,
                List<Cbc_ListCode> cac_CommodityClassification,
                Cac_ClassifiedTaxCategory cac_ClassifiedTaxCategory
            )
        {
            string cbc_UBLVersionID = UBLVERSIONID;
            string cbc_ID = Guid.NewGuid().ToString();

            Cac_Item_Claims claims = new Cac_Item_Claims(
                cbc_UBLVersionID,
                cbc_ID,
                cbc_Name,
                cac_SellersItemIdentification,
                cac_StandardItemIdentification,
                cac_CommodityClassification,
                cac_ClassifiedTaxCategory
            );

            return claims;
        }

        public static Cac_Item_SealedEnvelope NewItemCredential(string udid, VCTPS_VCA_SealedEnvelope vca, Cac_Item_Claims claims, ByteString proofSk, string nonce64)
        {
            Cac_Item_EnvelopeContent content = new Cac_Item_EnvelopeContent(udid, BTTGenericCredential.DefaultContext, udid, claims, null);
            List<string> types = new List<string>(BTTGenericCredential.RootType);
            types.Add(UBLItemType);
            string vca64 = Helpers.ToBase64String(vca.ToString());
            BTTGenericCredential_PackingLabel label = new BTTGenericCredential_PackingLabel(types,
                BTTGenericCredentialType.UBLDocument, 0, BTTTrustLevel.OberonProof, BTTEncryptionFlag.NotEncrypted, null, "Item " + udid, new List<string> { "Item " + udid }, vca64);
            Cac_Item_Envelope envelope = new Cac_Item_Envelope(udid, label, content);
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            string hashproof64 = ProofHelpers.ComputeHashProof(hash64, proofSk, nonce64);
            BTTGenericCredential_EnvelopeSeal proof = new BTTGenericCredential_EnvelopeSeal(hash64, hashproof64);
            Cac_Item_SealedEnvelope sealedenvelope = new Cac_Item_SealedEnvelope(envelope, proof);

            return sealedenvelope;
        }

        public static Cac_Party_Claims NewPartyClaims(
            Cbc_SchemeCode cbc_EndpointID,
            Cac_PartyIdentification cbc_PartyIdentification,
            Cac_PartyName cbc_PartyName,
            Cac_Address cac_PostalAddress,
            Cac_PartyTaxScheme cbc_PartyTaxScheme,

            string cac_PartyLegalEntityUdid,    // Cac_PartyLegalEntity_SealedEnvelope
            Cac_Contact cac_Contact,
            Cac_Person cac_Person
        )
        {
            string cbc_UBLVersionID = UBLVERSIONID;
            string cbc_ID = Guid.NewGuid().ToString();

            Cac_Party_Claims claims = new Cac_Party_Claims(
                cbc_UBLVersionID, 
                cbc_ID,
                cbc_EndpointID,
                cbc_PartyIdentification,
                cbc_PartyName,
                cac_PostalAddress,
                cbc_PartyTaxScheme,

                cac_PartyLegalEntityUdid,    // Cac_PartyLegalEntity_SealedEnvelope
                cac_Contact,
                cac_Person);

            return claims;
        }

        public static Cac_Party_SealedEnvelope NewPartyCredential(string udid, VCTPS_VCA_SealedEnvelope vca, Cac_Party_Claims claims, ByteString proofSk, string nonce64)
        {
            Cac_Party_EnvelopeContent content = new Cac_Party_EnvelopeContent(udid, BTTGenericCredential.DefaultContext, udid, claims, null);
            List<string> types = new List<string>(BTTGenericCredential.RootType);
            types.Add(UBLPartyType);
            string vca64 = Helpers.ToBase64String(vca.ToString());
            BTTGenericCredential_PackingLabel label = new BTTGenericCredential_PackingLabel(types,
                BTTGenericCredentialType.UBLDocument, 0, BTTTrustLevel.OberonProof, BTTEncryptionFlag.NotEncrypted, null, "Party " + udid, new List<string> { "Party " + udid }, vca64);
            Cac_Party_Envelope envelope = new Cac_Party_Envelope(udid, label, content);
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            string hashproof64 = ProofHelpers.ComputeHashProof(hash64, proofSk, nonce64);
            BTTGenericCredential_EnvelopeSeal proof = new BTTGenericCredential_EnvelopeSeal(hash64, hashproof64);
            Cac_Party_SealedEnvelope sealedenvelope = new Cac_Party_SealedEnvelope(envelope, proof);

            return sealedenvelope;
        }

        public static UBL21_Invoice2_Claims NewInvoiceClaims(
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

            Cac_AccountingSupplierParty cac_AccountingSupplierParty,
            Cac_AccountingCustomerParty cac_AccountingCustomerParty,
            Cac_PayeeParty cac_PayeeParty,

            Cac_Delivery cac_Delivery,

            Cac_PaymentMeans cac_PaymentMeans,
            Cac_PaymentTerms cac_PaymentTerms,
            List<Cac_AllowanceCharge> cac_AllowanceCharges,
            Cac_TaxTotal cac_TaxTotal,
            Cac_LegalMonetaryTotal cac_LegalMonetaryTotal,
            List<Cac_InvoiceLine> cac_InvoiceLine
        )
        {
            string cbc_UBLVersionID = UBLVERSIONID;
            string cbc_ID = Guid.NewGuid().ToString();

            UBL21_Invoice2_Claims claims = new UBL21_Invoice2_Claims(
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

        public static UBL21_Invoice2_SealedEnvelope NewInvoiceCredential(string udid, VCTPS_VCA_SealedEnvelope vca, UBL21_Invoice2_Claims claims, ByteString proofSk, string nonce64)
        {
            UBL21_Invoice2_EnvelopeContent content = new UBL21_Invoice2_EnvelopeContent(udid, BTTGenericCredential.DefaultContext, udid, claims, null);
            List<string> types = new List<string>(BTTGenericCredential.RootType);
            types.Add(UBLInvoiceType);
            string vca64 = Helpers.ToBase64String(vca.ToString());
            BTTGenericCredential_PackingLabel label = new BTTGenericCredential_PackingLabel(types,
                BTTGenericCredentialType.UBLDocument, 0, BTTTrustLevel.OberonProof, BTTEncryptionFlag.NotEncrypted, null, "Invoice " + udid, new List<string> { "Invoice " + udid }, vca64);
            UBL21_Invoice2_Envelope envelope = new UBL21_Invoice2_Envelope(udid, label, content);
            string json = envelope.ToString();
            string hash64 = SHA256Helpers.ComputeHash(json);
            string hashproof64 = ProofHelpers.ComputeHashProof(hash64, proofSk, nonce64);
            BTTGenericCredential_EnvelopeSeal proof = new BTTGenericCredential_EnvelopeSeal(hash64, hashproof64);
            UBL21_Invoice2_SealedEnvelope invoice = new UBL21_Invoice2_SealedEnvelope(envelope, proof);

            return invoice;
       }
    }
}
