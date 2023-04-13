using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DIDMaster
{
    public static class DidWeb7Method
    {
        public static string NewDid(DIDDocument didDocument) 
        { 
            string did = string.Empty;

            string didDoc = didDocument.ToString();
            string didDoc64 = DIDCommHelpers.Base64Encode(didDoc);

            did = "did:web7.0:diddoc:" + didDoc64;

            return did;
        }
    }
}
