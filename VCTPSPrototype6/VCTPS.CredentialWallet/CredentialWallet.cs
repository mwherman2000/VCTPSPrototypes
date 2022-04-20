using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VCTPS.UBL22.Credentials;
using VCTPS.Common;
using Google.Protobuf;
using VCTPS.Protocol;

namespace VCTPS.CredentialWallet
{
    public static class WalletHelpers
    {
        public static readonly string DefaultNonce64 = Helpers.ToBase64String("Password1");

        public enum RegistryType
        {
            Item,
            Party,
            Invoice
        }

        public static Dictionary<string, Cac_Item_SealedEnvelope> ItemCatalog = new Dictionary<string, Cac_Item_SealedEnvelope>();
        public static Dictionary<string, Cac_Party_SealedEnvelope> PartyDirectory = new Dictionary<string, Cac_Party_SealedEnvelope>();
        public static Dictionary<string, UBL22_Invoice_SealedEnvelope> InvoiceJournal = new Dictionary<string, UBL22_Invoice_SealedEnvelope>();

        public static string FindKey(string name, RegistryType type)
        {
            string keyid = "";

            switch (type)
            {
                case RegistryType.Item:
                    {
                        foreach (Cac_Item_SealedEnvelope ss in ItemCatalog.Values)
                        {
                            Cac_Item_Claims claims = (Cac_Item_Claims)ss.envelope.content.claims;
                            if (claims.cbc_Name == name)
                            {
                                keyid = ss.envelope.udid;
                                break;
                            }
                        }
                        break;
                    }
                case RegistryType.Party:
                    {
                        foreach (Cac_Party_SealedEnvelope ss in PartyDirectory.Values)
                        {
                            Cac_Party_Claims claims = (Cac_Party_Claims)ss.envelope.content.claims;
                            Cac_Person person = claims.cac_Person;
                            if (person.cbc_FirstName + " " + person.cbc_FamilyName == name)
                            {
                                keyid = ss.envelope.udid;
                                break;
                            }
                        }
                        break;
                    }
                case RegistryType.Invoice:
                    {
                        foreach (UBL22_Invoice_SealedEnvelope ss in InvoiceJournal.Values)
                        {
                            UBL22_Invoice_Claims claims = (UBL22_Invoice_Claims)ss.envelope.content.claims;
                            if (claims.cbc_ID == name)
                            {
                                keyid = ss.envelope.udid;
                                break;
                            }
                        }
                        break;
                    }
                default:
                    break;
            }

            return keyid;
        }

        public static void InitializeItems()
        {
            {
                GenericSubject subject = KeyVault.Add("cabbages");
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                List<Cbc_ListCode> commodityclassification = new List<Cbc_ListCode>() { new Cbc_ListCode("1234", "1234", "1234") };
                Cac_Item_Claims subject_claims = UBL22CredentialFactory.NewItemClaims(
                    subject.Name,
                    new Cac_SellersItemIdentification(udid),
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    commodityclassification,
                    new Cac_ClassifiedTaxCategory(new Cbc_SchemeCode("1234", "1234", "1234"), 10, new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))
                    ));
                string claimsJson = subject_claims.ToString();

                Cac_Item_SealedEnvelope subject_credential = UBL22CredentialFactory.NewItemCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                ItemCatalog.Add(subject.KeyId, subject_credential);
            }

            {
                GenericSubject subject = KeyVault.Add("carrots");
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                List<Cbc_ListCode> commodityclassification = new List<Cbc_ListCode>() { new Cbc_ListCode("1234", "1234", "1234") };
                Cac_Item_Claims subject_claims = UBL22CredentialFactory.NewItemClaims(
                    subject.Name,
                    new Cac_SellersItemIdentification(udid),
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    commodityclassification,
                    new Cac_ClassifiedTaxCategory(new Cbc_SchemeCode("1234", "1234", "1234"), 10, new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))
                    ));
                string claimsJson = subject_claims.ToString();

                Cac_Item_SealedEnvelope subject_credential = UBL22CredentialFactory.NewItemCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                ItemCatalog.Add(udid, subject_credential);
            }

            {
                GenericSubject subject = KeyVault.Add("cauliflower");
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                List<Cbc_ListCode> commodityclassification = new List<Cbc_ListCode>() { new Cbc_ListCode("1234", "1234", "1234") };
                Cac_Item_Claims subject_claims = UBL22CredentialFactory.NewItemClaims(
                    subject.Name,
                    new Cac_SellersItemIdentification(udid),
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    commodityclassification,
                    new Cac_ClassifiedTaxCategory(new Cbc_SchemeCode("1234", "1234", "1234"), 10, new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))
                    ));
                string claimsJson = subject_claims.ToString();

                Cac_Item_SealedEnvelope subject_credential = UBL22CredentialFactory.NewItemCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                ItemCatalog.Add(udid, subject_credential);
            }
        }

        public static void InitializeParties()
        {
            // "Mary's Market Garden
            {
                GenericSubject subject = KeyVault.Add("Mark Accounting");
                subject.OrgName = "Mary's Market Garden";
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                Cac_Address postalAddress = new Cac_Address(Guid.NewGuid().ToString(), "PO Box 45", "1234 Mary Street", null, "1234",
                    "Accounting", "Mary", "12345", "MA", new Cac_Country(new Cbc_ListCode("1234", "1234", "1234")));
                string cac_PartyLegalEntityUdid = ""; // TODO
                Cac_Contact contact = new Cac_Contact("+1 212 123-1234", null, "mark@marysmarketgarden.local");
                Cac_Person person = new Cac_Person("Mark", "M.", "Accounting", "Accounting Clerk");
                Cac_Party_Claims subject_claims = UBL22CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL22CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                PartyDirectory.Add(subject.KeyId, subject_credential);
            }

            {
                GenericSubject subject = KeyVault.Add("Melanie Sales");
                subject.OrgName = "Mary's Market Garden";
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                Cac_Address postalAddress = new Cac_Address(Guid.NewGuid().ToString(), "PO Box 45", "1234 Mary Street", null, "1234",
                    "Sales", "Mary", "12345", "MA", new Cac_Country(new Cbc_ListCode("1234", "1234", "1234")));
                string cac_PartyLegalEntityUdid = ""; // TODO
                Cac_Contact contact = new Cac_Contact("+1 212 123-1234", null, "melanie@marysmarketgarden.local");
                Cac_Person person = new Cac_Person("Melanie", "M.", "Sales", "Sales Manager");
                Cac_Party_Claims subject_claims = UBL22CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL22CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                PartyDirectory.Add(subject.KeyId, subject_credential);
            }

            {
                GenericSubject subject = KeyVault.Add("Mo Shipping");
                subject.OrgName = "Mary's Market Garden";
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                Cac_Address postalAddress = new Cac_Address(Guid.NewGuid().ToString(), "PO Box 45", "1234 Mary Street", null, "1234",
                    "Warehouse", "Mary", "12345", "MA", new Cac_Country(new Cbc_ListCode("1234", "1234", "1234")));
                string cac_PartyLegalEntityUdid = ""; // TODO
                Cac_Contact contact = new Cac_Contact("+1 212 123-1234", null, "mo@marysmarketgarden.local");
                Cac_Person person = new Cac_Person("Mo", "M.", "Shipping", "Shipper");
                Cac_Party_Claims subject_claims = UBL22CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL22CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                PartyDirectory.Add(subject.KeyId, subject_credential);
            }

            // David's Cabbages
            {
                GenericSubject subject = KeyVault.Add("Darla Accounting");
                subject.OrgName = "David's Cabbages";
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                Cac_Address postalAddress = new Cac_Address(Guid.NewGuid().ToString(), "PO Box 45", "1234 David Street", null, "1234",
                    "Accounting", "David", "12345", "DE", new Cac_Country(new Cbc_ListCode("1234", "1234", "1234")));
                string cac_PartyLegalEntityUdid = ""; // TODO
                Cac_Contact contact = new Cac_Contact("+1 302 123-1234", null, "darla@davidscabbages.local");
                Cac_Person person = new Cac_Person("Darla", "D.", "Accounting", "Accounting Clerk");
                Cac_Party_Claims subject_claims = UBL22CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL22CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                PartyDirectory.Add(subject.KeyId, subject_credential);
            }

            {
                GenericSubject subject = KeyVault.Add("Dean Sales");
                subject.OrgName = "David's Cabbages";
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                Cac_Address postalAddress = new Cac_Address(Guid.NewGuid().ToString(), "PO Box 45", "1234 David Street", null, "1234",
                    "Sales", "David", "12345", "DE", new Cac_Country(new Cbc_ListCode("1234", "1234", "1234")));
                string cac_PartyLegalEntityUdid = ""; // TODO
                Cac_Contact contact = new Cac_Contact("+1 302 123-1234", null, "dean@davidscabbages.local");
                Cac_Person person = new Cac_Person("Dean", "M.", "Sales", "Sales Manager");
                Cac_Party_Claims subject_claims = UBL22CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL22CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                PartyDirectory.Add(subject.KeyId, subject_credential);
            }

            {
                GenericSubject subject = KeyVault.Add("Donna Shipping");
                subject.OrgName = "David's Cabbages";
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                Cac_Address postalAddress = new Cac_Address(Guid.NewGuid().ToString(), "PO Box 45", "1234 David Street", null, "1234",
                    "Warehouse", "David", "12345", "DE", new Cac_Country(new Cbc_ListCode("1234", "1234", "1234")));
                string cac_PartyLegalEntityUdid = ""; // TODO
                Cac_Contact contact = new Cac_Contact("+1 302 123-1234", null, "donna@davidscabbages.local");
                Cac_Person person = new Cac_Person("Donna", "D.", "Shipping", "Shipper");
                Cac_Party_Claims subject_claims = UBL22CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL22CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                PartyDirectory.Add(subject.KeyId, subject_credential);
            }

            // Paul's Produce
            {
                GenericSubject subject = KeyVault.Add("Pat Accounting");
                subject.OrgName = "Paul's Produce";
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                Cac_Address postalAddress = new Cac_Address(Guid.NewGuid().ToString(), "PO Box 45", "1234 Paul Street", null, "1234",
                    "Accounting", "Paul", "12345", "PA", new Cac_Country(new Cbc_ListCode("1234", "1234", "1234")));
                string cac_PartyLegalEntityUdid = ""; // TODO
                Cac_Contact contact = new Cac_Contact("+1 215 123-1234", null, "paul@paulsproduce.local");
                Cac_Person person = new Cac_Person("Pat", "P.", "Accounting", "Accounting Clerk");
                Cac_Party_Claims subject_claims = UBL22CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL22CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                PartyDirectory.Add(subject.KeyId, subject_credential);
            }

            {
                GenericSubject subject = KeyVault.Add("Peter Sales");
                subject.OrgName = "Paul's Produce";
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                Cac_Address postalAddress = new Cac_Address(Guid.NewGuid().ToString(), "PO Box 45", "1234 Paul Street", null, "1234",
                    "Sales", "Paul", "12345", "PA", new Cac_Country(new Cbc_ListCode("1234", "1234", "1234")));
                string cac_PartyLegalEntityUdid = ""; // TODO
                Cac_Contact contact = new Cac_Contact("+1 215 123-1234", null, "peter@paulsproduce.local");
                Cac_Person person = new Cac_Person("Peter", "P.", "Sales", "Sales Manager");
                Cac_Party_Claims subject_claims = UBL22CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL22CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                PartyDirectory.Add(subject.KeyId, subject_credential);
            }

            {
                GenericSubject subject = KeyVault.Add("Polly Shipping");
                subject.OrgName = "Paul's Produce";
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                Cac_Address postalAddress = new Cac_Address(Guid.NewGuid().ToString(), "PO Box 45", "1234 Paul Street", null, "1234",
                    "Warehouse", "Paul", "12345", "PA", new Cac_Country(new Cbc_ListCode("1234", "1234", "1234")));
                string cac_PartyLegalEntityUdid = ""; // TODO
                Cac_Contact contact = new Cac_Contact("+1 215 123-1234", null, "polly@paulsproduce.local");
                Cac_Person person = new Cac_Person("Polly", "P.", "Shipping", "Shipper");
                Cac_Party_Claims subject_claims = UBL22CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL22CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                PartyDirectory.Add(subject.KeyId, subject_credential);
            }

            // Shippers/Freight Forwarders
            {
                GenericSubject subject = KeyVault.Add("Freddy Forwarder");
                subject.OrgName = "FedExpress Freight";
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                Cac_Address postalAddress = new Cac_Address(Guid.NewGuid().ToString(), "PO Box 45", "1234 Fed Street", null, "1234",
                    "Dispatch", "Fed", "12345", "FL", new Cac_Country(new Cbc_ListCode("1234", "1234", "1234")));
                string partylegalentityudid = "5678"; // TODO
                Cac_Contact contact = new Cac_Contact("+1 689 123-1234", null, "freddy@fedexpress.local");
                Cac_Person person = new Cac_Person("Freddy", "F.", "Forwarder", "Freight Forwarder");
                Cac_Party_Claims subject_claims = UBL22CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    partylegalentityudid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL22CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                PartyDirectory.Add(subject.KeyId, subject_credential);
            }

            {
                GenericSubject subject = KeyVault.Add("Darryl Forwarder");
                subject.OrgName = "DHLorries Freight";
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                Cac_Address postalAddress = new Cac_Address(Guid.NewGuid().ToString(), "PO Box 45", "1234 Ech Street", null, "1234",
                    "Dispatch", "Ech", "12345", "NY", new Cac_Country(new Cbc_ListCode("1234", "1234", "1234")));
                string partylegalentityudid = "5678"; // TODO
                Cac_Contact contact = new Cac_Contact("+1 212 123-1234", null, "darryl@dhlorries.local");
                Cac_Person person = new Cac_Person("Darryl", "D.", "Forwarder", "Freight Forwarder");
                Cac_Party_Claims subject_claims = UBL22CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    partylegalentityudid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL22CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                PartyDirectory.Add(subject.KeyId, subject_credential);
            }

            {
                GenericSubject subject = KeyVault.Add("Ursala Forwarder");
                subject.OrgName = "UPPronto Freight";
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                Cac_Address postalAddress = new Cac_Address(Guid.NewGuid().ToString(), "PO Box 45", "1234 Pronto Street", null, "1234",
                    "Dispatch", "Pronto", "12345", "PA", new Cac_Country(new Cbc_ListCode("1234", "1234", "1234")));
                string partylegalentityudid = "5678"; // TODO
                Cac_Contact contact = new Cac_Contact("+1 215 123-1234", null, "ursala@uppronto.local");
                Cac_Person person = new Cac_Person("Ursala", "U.", "Forwarder", "Fright Forwarder");
                Cac_Party_Claims subject_claims = UBL22CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    partylegalentityudid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL22CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                PartyDirectory.Add(subject.KeyId, subject_credential);
            }

            // Bob Buyer @ ABC Grocery
            {
                GenericSubject subject = KeyVault.Add("Bob Buyer");
                subject.OrgName = "ABC Grocery";
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, null, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                Cac_Address postalAddress = new Cac_Address(Guid.NewGuid().ToString(), "PO Box 45", "1234 ABC Street", null, "1234",
                    "Dispatch", "ABC", "12345", "AL", new Cac_Country(new Cbc_ListCode("1234", "1234", "1234")));
                string partylegalentityudid = "5678"; // TODO
                Cac_Contact contact = new Cac_Contact("+1 205 123-1234", null, "bob@abcgrocery.local");
                Cac_Person person = new Cac_Person("Bob", "B.", "Buyer", "Buyer");
                Cac_Party_Claims subject_claims = UBL22CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    partylegalentityudid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL22CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                PartyDirectory.Add(subject.KeyId, subject_credential);
            }
        }

        public static void InitializeBusinessDocuments()
        {
            // Create a sample Invoice from David's Cabbages to Bob Buyer at ABC Grocery
            {
                GenericSubject subject = KeyVault.Add("Invoice 1234");
                subject.OrgName = "David's Cabbages";
                string udid = subject.KeyId;
                List<string> rights = new List<string>() { "read" };
                List<string> processing = new List<string> { "accept", "reject" };
                ByteString proofSk = subject.ProofKey.Sk;

                VCTPS_VCA_SealedEnvelope vca = VCTPSCredentialFactory.NewVCACredential("*", udid, rights, null, processing, proofSk, DefaultNonce64);
                string vcaJson = vca.ToString();

                Cac_AccountingCustomerParty accountingcustomerparty = new Cac_AccountingCustomerParty(WalletHelpers.FindKey("Bob Buyer", RegistryType.Party));
                Cac_AccountingSupplierParty accountingsupplierparty = new Cac_AccountingSupplierParty(WalletHelpers.FindKey("Mark Accounting", RegistryType.Party));
                Cac_PayeeParty payeeparty = new Cac_PayeeParty(WalletHelpers.FindKey("Mark Accounting", RegistryType.Party));
                string deliverykey = WalletHelpers.FindKey("Bob Buyer", RegistryType.Party);
                Cac_Party_Claims deliveryclaims = (Cac_Party_Claims)PartyDirectory[deliverykey].envelope.content.claims;
                Cac_Address deliveryaddress = deliveryclaims.cac_PostalAddress;
                string payeefinancialaccountudid = "5678"; //TODO
                string cabbagesitemid = WalletHelpers.FindKey("cabbages", RegistryType.Item);
                Cac_InvoiceLine line1 = new Cac_InvoiceLine(
                    Guid.NewGuid().ToString(),
                    new Cbc_Note(ISO639_1_LanguageCodes.en, "Cabbages - 100 lbs"),
                    new Cbc_Quantity("lb", 100),
                    new Cbc_Amount("USD", 20.80),
                    "1234",
                    new Cac_OrderLineReference("1"),
                    new List<Cac_AllowanceCharge> { new Cac_AllowanceCharge(true, "abcd", new Cbc_Amount("USD", 1.00)) },
                    new Cac_TaxTotal(new Cbc_Amount("USD", 1.00)),
                    cabbagesitemid,
                    new Cac_Price(new Cbc_Amount("USD", 20.80)));
              
                UBL22_Invoice_Claims subject_claims = UBL22CredentialFactory.NewInvoiceClaims(DateTime.UtcNow,
                    new Cbc_ListCode("1234", "1234", "1234"),
                    new Cbc_Note(ISO639_1_LanguageCodes.en, "Invoice 1234 for ABC Cabbages for 100 lb. of cabbages"),
                    DateTime.UtcNow,
                    new Cbc_ListCode("1234", "1234", "1234"),
                    "1234.00",
                    new Cbc_TimePeriod(DateTime.UtcNow, DateTime.UtcNow.AddDays(30)),
                    new Cbc_OrderReference("1234"),
                    new Cac_DocumentReference("1234", "Supplemental Documentation", new Cac_Attachment(new Cac_ExternalReference("http://example.com/s1"))),
                    new List<Cac_DocumentReference> { },
                    accountingsupplierparty, accountingcustomerparty, payeeparty,
                    new Cac_Delivery(DateTime.UtcNow, new Cac_DeliveryLocation(new Cbc_SchemeCode("1234", "1234", "1234"), deliveryaddress)),
                    new Cac_PaymentMeans(new Cbc_ListCode("1234", "1234", "1234"), DateTime.UtcNow, "1234", "1234", payeefinancialaccountudid),
                    new Cac_PaymentTerms(new Cbc_Note(ISO639_1_LanguageCodes.en, "Net 30")),
                    new List<Cac_AllowanceCharge> { new Cac_AllowanceCharge(true, "abcd", new Cbc_Amount("USD", 10.0))},
                    new Cac_TaxTotal(new Cbc_Amount("USD", 12.34)),
                    new Cac_LegalMonetaryTotal(new Cbc_Amount("USD", 12.34), new Cbc_Amount("USD", 12.34), new Cbc_Amount("USD", 12.34), new Cbc_Amount("USD", 12.34), new Cbc_Amount("USD", 12.34), new Cbc_Amount("USD", 12.34), new Cbc_Amount("USD", 12.34), new Cbc_Amount("USD", 12.34)),
                    new List<Cac_InvoiceLine> { line1 });
                string claimsJson = subject_claims.ToString();

                UBL22_Invoice_SealedEnvelope subject_credential = UBL22CredentialFactory.NewInvoiceCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                InvoiceJournal.Add(subject.KeyId, subject_credential);
            }

        }
    }
}
