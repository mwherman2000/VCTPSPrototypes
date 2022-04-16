using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VCTPSCommon
{
    public static class KeyVault
    {
        public static Dictionary<string, GenericSubject> Vault = new Dictionary<string, GenericSubject>();
        private static bool initialized = false;

        private static void Initialize()
        {
            KeyVault.Add("Charlie");
            KeyVault.Add("Delta");
            KeyVault.Add("Echo");
            initialized = true;
        }

        public static GenericSubject Add(string name)
        {
            GenericSubject s = new GenericSubject(name);
            Vault.Add(s.KeyId, s);

            return s;
        }

        public static GenericSubject Find(string name)
        {
            GenericSubject s = null;

            if (!initialized) Initialize();

            foreach (GenericSubject ss in KeyVault.Vault.Values)
            {
                if (ss.Name == name)
                {
                    s = ss;   
                    break;
                }
            }

            return s;
        }

        public static string FindKey(string name)
        {
            string keyid = "";

            if (!initialized) Initialize();

            foreach (GenericSubject ss in KeyVault.Vault.Values)
            {
                if (ss.Name == name)
                {
                    keyid = ss.KeyId;
                    break;
                }
            }

            return keyid;
        }
    }
}
