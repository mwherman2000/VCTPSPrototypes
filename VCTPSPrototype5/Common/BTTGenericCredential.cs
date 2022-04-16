using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VCTPSCommon
{
    public static class BTTGenericCredential
    {
        public const string DefaultVCAType = "Verifiable Capability Authorization";

        public static readonly List<string> DefaultContext = new List<string> {"https://www.sovrona.com/ns/svrn/v1" };
        public static readonly List<string> RootType = new List<string> { "Verifiable Credential", "Structured Credential" };
    }
}
