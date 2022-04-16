using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VCTPS.UBL21Credentials;
using VCTPS.Common;
using Google.Protobuf;
using VCTPS.Protocol;

namespace VCTPS.CredentialWallet
{
    public static class CredentialWallet
    {
        public static readonly string DefaultNonce64 = Helpers.ToBase64String("Password1");

        public enum RegistryType
        {
            Item,
            Party,
            Invoice2
        }

        public static Dictionary<string, Cac_Item_SealedEnvelope> ItemCatalog = new Dictionary<string, Cac_Item_SealedEnvelope>();
        public static Dictionary<string, Cac_Party_SealedEnvelope> PartyDirectory = new Dictionary<string, Cac_Party_SealedEnvelope>();
        public static Dictionary<string, UBL21_Invoice2_SealedEnvelope> Invoice2Journal = new Dictionary<string, UBL21_Invoice2_SealedEnvelope>();

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
                case RegistryType.Invoice2:
                    {
                        foreach (UBL21_Invoice2_SealedEnvelope ss in Invoice2Journal.Values)
                        {
                            UBL21_Invoice2_Claims claims = (UBL21_Invoice2_Claims)ss.envelope.content.claims;
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
                Cac_Item_Claims subject_claims = UBL21CredentialFactory.NewItemClaims(
                    subject.Name,
                    new Cac_SellersItemIdentification(udid),
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    commodityclassification,
                    new Cac_ClassifiedTaxCategory(new Cbc_SchemeCode("1234", "1234", "1234"), 10, new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))
                    ));
                string claimsJson = subject_claims.ToString();

                Cac_Item_SealedEnvelope subject_credential = UBL21CredentialFactory.NewItemCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
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
                Cac_Item_Claims subject_claims = UBL21CredentialFactory.NewItemClaims(
                    subject.Name,
                    new Cac_SellersItemIdentification(udid),
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    commodityclassification,
                    new Cac_ClassifiedTaxCategory(new Cbc_SchemeCode("1234", "1234", "1234"), 10, new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))
                    ));
                string claimsJson = subject_claims.ToString();

                Cac_Item_SealedEnvelope subject_credential = UBL21CredentialFactory.NewItemCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
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
                Cac_Item_Claims subject_claims = UBL21CredentialFactory.NewItemClaims(
                    subject.Name,
                    new Cac_SellersItemIdentification(udid),
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    commodityclassification,
                    new Cac_ClassifiedTaxCategory(new Cbc_SchemeCode("1234", "1234", "1234"), 10, new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))
                    ));
                string claimsJson = subject_claims.ToString();

                Cac_Item_SealedEnvelope subject_credential = UBL21CredentialFactory.NewItemCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
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
                Cac_Party_Claims subject_claims = UBL21CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL21CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
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
                Cac_Party_Claims subject_claims = UBL21CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL21CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
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
                Cac_Party_Claims subject_claims = UBL21CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL21CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
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
                Cac_Party_Claims subject_claims = UBL21CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL21CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
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
                Cac_Party_Claims subject_claims = UBL21CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL21CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
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
                Cac_Party_Claims subject_claims = UBL21CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL21CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
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
                Cac_Party_Claims subject_claims = UBL21CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL21CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
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
                Cac_Party_Claims subject_claims = UBL21CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL21CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
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
                Cac_Party_Claims subject_claims = UBL21CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL21CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
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
                string cac_PartyLegalEntityUdid = ""; // TODO
                Cac_Contact contact = new Cac_Contact("+1 689 123-1234", null, "freddy@fedexpress.local");
                Cac_Person person = new Cac_Person("Freddy", "F.", "Forwarder", "Freight Forwarder");
                Cac_Party_Claims subject_claims = UBL21CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL21CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
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
                string cac_PartyLegalEntityUdid = ""; // TODO
                Cac_Contact contact = new Cac_Contact("+1 212 123-1234", null, "darryl@dhlorries.local");
                Cac_Person person = new Cac_Person("Darryl", "D.", "Forwarder", "Freight Forwarder");
                Cac_Party_Claims subject_claims = UBL21CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL21CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
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
                string cac_PartyLegalEntityUdid = ""; // TODO
                Cac_Contact contact = new Cac_Contact("+1 215 123-1234", null, "ursala@uppronto.local");
                Cac_Person person = new Cac_Person("Ursala", "U.", "Forwarder", "Fright Forwarder");
                Cac_Party_Claims subject_claims = UBL21CredentialFactory.NewPartyClaims(
                    new Cbc_SchemeCode("1234", "1234", "1234"),
                    new Cac_PartyIdentification(new Cbc_SchemeCode("1234", "1234", "1234")),
                    new Cac_PartyName(subject.OrgName),
                    postalAddress,
                    new Cac_PartyTaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"), new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))),
                    cac_PartyLegalEntityUdid, contact, person);
                string claimsJson = subject_claims.ToString();

                Cac_Party_SealedEnvelope subject_credential = UBL21CredentialFactory.NewPartyCredential(udid, vca, subject_claims, proofSk, DefaultNonce64);
                string sealedEnvelopeJson = subject_credential.ToString();

                PartyDirectory.Add(subject.KeyId, subject_credential);
            }
        }
    }
}
