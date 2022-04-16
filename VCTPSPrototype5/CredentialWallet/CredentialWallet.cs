using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UBL21Credentials;
using VCTPSCommon;
using Google.Protobuf;
using VCTPSProtocol;

namespace CredentialWallet
{

    public static class WalletHelpers
    {
        public static readonly string DefaultNonce64 = Helpers.ToBase64String("Password1");

        public static Dictionary<string, Cac_Item_SealedEnvelope> ItemCatalog = new Dictionary<string, Cac_Item_SealedEnvelope>();
        public static void InitializeItems()
        {
            GenericSubject cabbages = KeyVault.Add("cabbages");
            string cabbages_udid = cabbages.KeyId;
            List<string> rights = new List<string>() { "read" };
            ByteString proofSk = cabbages.ProofKey.Sk;

            List<Cbc_ListCode> commodityclassification = new List<Cbc_ListCode>() { new Cbc_ListCode("1234", "1234", "1234") };
            Cac_Item_Claims cabbages_claims = UBL21CredentialFactory.NewItemClaims(
                "cabbages",
                new Cac_SellersItemIdentification(cabbages_udid),
                new Cbc_SchemeCode("1234", "1234", "1234"),
                commodityclassification,
                new Cac_ClassifiedTaxCategory(new Cbc_SchemeCode("1234", "1234", "1234"), 10, new Cac_TaxScheme(new Cbc_SchemeCode("1234", "1234", "1234"))
                ));
            string claimsJson = cabbages_claims.ToString();

            VCTPS_VCA_SealedEnvelope cabbages_vca = VCTPSCredentialFactory.NewVCACredential("*", cabbages_udid, rights, null, null, proofSk, DefaultNonce64);
            Cac_Item_SealedEnvelope cabbages_credential = UBL21CredentialFactory.NewItemCredential(cabbages_udid, cabbages_vca, cabbages_claims, proofSk, DefaultNonce64);
            string sealedEnvelopeJson  = cabbages_credential.ToString();

            ItemCatalog.Add(cabbages_udid, cabbages_credential);
        }
    }
}
