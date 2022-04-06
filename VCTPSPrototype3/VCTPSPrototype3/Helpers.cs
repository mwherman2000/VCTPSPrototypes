using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VCTPSPrototype3
{
    public static class Helpers
    {
        static System.Reflection.Assembly assembly = typeof(Program).Assembly;

        public static string GetTemplate(string resname)
        {
            var streams = assembly.GetManifestResourceNames();
            var nfeJsonEnvelopeStream = assembly.GetManifestResourceStream(resname);
            if (nfeJsonEnvelopeStream == null) return "";
            byte[] res = new byte[nfeJsonEnvelopeStream.Length];
            int nBytes = nfeJsonEnvelopeStream.Read(res);
            string template = Encoding.UTF8.GetString(res);

            return template;
        }
    }
}
