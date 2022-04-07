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

        public static string SendMessage(string url, string jsonRequest)
        {
            string jsonResponse;

            using (var httpClient = new HttpClient())
            {
                Console.WriteLine(">>>Agent Url:" + url);
                using (var requestMessage = new HttpRequestMessage(new HttpMethod("POST"), url))
                {
                    requestMessage.Headers.TryAddWithoutValidation("Accept", "application/json");
                    Console.WriteLine(">>>Request:" + jsonRequest);
                    requestMessage.Content = new StringContent(jsonRequest);
                    var task = httpClient.SendAsync(requestMessage);
                    task.Wait();
                    var result = task.Result;
                    jsonResponse = result.Content.ReadAsStringAsync().Result;
                    Console.WriteLine(">>>Response:" + url);
                }
            }
            return jsonResponse;
        }
    }
}
