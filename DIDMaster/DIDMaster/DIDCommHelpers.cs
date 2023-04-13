using Google.Protobuf;
using Okapi.Keys.V1;
using Okapi.Transport;
using Okapi.Transport.V1;
using Pbmse.V1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace DIDMaster;

public static class DIDCommHelpers
{
    static System.Reflection.Assembly assembly = typeof(Program).Assembly;
    static private long MessagesReceived = 0;

    public static string GetTemplate(string resname)
    {
        var streams = assembly.GetManifestResourceNames();
        var nfeJsonEnvelopeStream = assembly.GetManifestResourceStream(resname);
        if (nfeJsonEnvelopeStream == null) return "";
        byte[] res = new byte[nfeJsonEnvelopeStream.Length];
        int nBytes = nfeJsonEnvelopeStream.Read(res);
        string template = Encoding.UTF8.GetString(res);

        if (String.IsNullOrEmpty(template)) throw new NullReferenceException("GetTemplate");

        return template;
    }
 
    public static int HttpMessagesSent = 0;
    public static int DIDCommMessageRequestsSent = 0;
    static readonly HttpClient httpClient = new HttpClient(); 
    // https://www.thecodebuzz.com/using-httpclient-best-practices-and-anti-patterns/

    private static string SendHttpMessage(string url, string jsonMessageRequest)
    {
        string jsonResponse = "{ }";

        HttpMessagesSent++;
        Console.WriteLine("SendHTTPCOMMMessage: " 
            + DIDCommHelpers.DIDCommMessageRequestsSent.ToString() + " DIDComm sent. " 
            + DIDCommHelpers.HttpMessagesSent.ToString() + " HTTP sent. " 
            + MessagesReceived.ToString() + " HTTP rcvd.");

        Console.WriteLine(">>>Agent Url:" + url);
        using (var requestMessage = new HttpRequestMessage(new HttpMethod("POST"), url))
        {
            requestMessage.Headers.TryAddWithoutValidation("Accept", "application/json");
            Console.WriteLine(">>>Request:" + jsonMessageRequest);
            requestMessage.Content = new StringContent(jsonMessageRequest);
            var task = httpClient.SendAsync(requestMessage);
            task.Wait();  // if an exception is thrown here, you likely forgot to run Visual Studio in "Run as Administrator" mode
            //var result = task.Result;
            //jsonResponse = result.Content.ReadAsStringAsync().Result;
            //Console.WriteLine(">>>Response:" + url);
        }

        return jsonResponse;
    }

    public static void SendDIDCommMessageRequest(string DIDCommEndpointUrl, CoreMessage core)
    {
        foreach (var to in core.To.ToList())
        {
            DIDCommHelpers.SendDIDCommMessageRequest(DIDCommEndpointUrl, core.From, to, core);
        }
    }

    public static string SendDIDCommMessageRequest(string DIDCommEndpointUrl, string from, string to, CoreMessage core)
    {
        string jsonResponse = "{ }";

        Console.WriteLine("SendDIDCommMessageRequest: "
            + DIDCommHelpers.DIDCommMessageRequestsSent.ToString() + " DIDComm sent. "
            + DIDCommHelpers.HttpMessagesSent.ToString() + " HTTP sent. "
            + MessagesReceived.ToString() + " HTTP rcvd.");

        var senderDIDDoc = Subjects.MyPersonification.GetDIDDocument(from, "", "", 0, false);
        JsonWebKey mySenderKey = Subjects.MyPersonification.SecretKey;
        var receiverDIDDoc = Subjects.MyPersonification.GetDIDDocument(to, "", "", 0, false);
        JsonWebKey myReceiverKey = Subjects.MyPersonification.PublicKey;

        Console.WriteLine(">>Sending to: " + receiverDIDDoc.comment + "\t" + to); ;
        PackRequest pr = new PackRequest()
        {
            Plaintext = core.ToByteString(),
            SenderKey = mySenderKey,
            ReceiverKey = myReceiverKey,
            Mode = EncryptionMode.Direct
        };
        var packResponse = DIDComm.Pack(pr);
        var encryptedMessage = packResponse.Message;
        DIDCommEncryptedMessage64 encryptedMessage64 = new DIDCommEncryptedMessage64(
            encryptedMessage.Iv.ToBase64(),
            encryptedMessage.Ciphertext.ToBase64(),
            encryptedMessage.Tag.ToBase64(),
            recipients64: new List<string>() { encryptedMessage.Recipients[0].ToByteString().ToBase64() }
        );

        DIDCommMessageRequest messageRequest = new DIDCommMessageRequest(encryptedMessage64);
        var jsonMessageRequest = messageRequest.ToString();

        // Perform async HTTP POST
        var task = Task.Run(() => DIDCommHelpers.SendHttpMessage(DIDCommEndpointUrl, jsonMessageRequest));
        DIDCommMessageRequestsSent++;

        return jsonResponse;
    }

    public static string Base64Encode(string plainText)
    {
        var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
        return System.Convert.ToBase64String(plainTextBytes);
    }

    public static string Base64Decode(string base64EncodedData)
    {
        var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
        return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
    }
}
