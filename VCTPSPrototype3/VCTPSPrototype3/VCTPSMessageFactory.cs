using Google.Protobuf;
using Okapi.Examples;
using Okapi.Examples.V1;
using Okapi.Transport;
using Okapi.Transport.V1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VCTPSPrototype3
{
    public static class VCTPSMessageFactory
    {
        // NewPollMsg: Do you have anything to send me? If you do, send me a 'notify' message with a VCA (which includes a payload identifier)
        public static CoreMessage NewPollMsg(string from, string[] to, long expires = 0)
        {
            CoreMessage core = new CoreMessage();

            core.Id = Guid.NewGuid().ToString();
            core.Type = "https://example.org/vctp/1.0/poll";

            var message = new BasicMessage();
            message.Text = "{ }";
            core.Body = message.ToByteString();

            core.Expires = expires;

            core.From = from;
            core.To.Add(to);

            return core;
        }

        // NewNotifyMsg: I have a payload for you. Here's a VCA (which includes a payload identifier) for you to acknowledge and agree to.
        //               Send me a 'pull' message containing a VCA Acknowledgement confirming your agreement with the VCA and I'll send you the payload
        public static CoreMessage NewNotifyMsg(string from, string[] to, string vcaJson, long expires = 0)
        {
            CoreMessage core = new CoreMessage();

            core.Id = Guid.NewGuid().ToString();
            core.Type = "https://example.org/vctp/1.0/notify";

            var message = new BasicMessage();
            message.Text = String.Format("{{ vca : {0} }}", vcaJson);
            core.Body = message.ToByteString();

            core.Expires = expires;

            core.From = from;
            core.To.Add(to);

            return core;
        }

        // NewPullMsg: Here's a VCA Acknowledgement confirming that I agree to the VCA (which includes a payload identifier).
        //             Please send me a copy of the corresponding payload
        public static CoreMessage NewPullMsg(string from, string[] to, string vcaackJson, long expires = 0)
        {
            CoreMessage core = new CoreMessage();

            core.Id = Guid.NewGuid().ToString();
            core.Type = "https://example.org/vctp/1.0/pull";

            var message = new BasicMessage();
            message.Text = String.Format("{{ vcaack : {0} }}", vcaackJson);
            core.Body = message.ToByteString();

            core.Expires = expires;

            core.From = from;
            core.To.Add(to);

            return core;
        }

        // NewPushMsg: Here's the payload you requested (and the corresponding VCA Acknowledgement you agreed to)
        public static CoreMessage NewPushMsg(string from, string[] to, string vcaackJson, string payloadJson, long expires = 0)
        {
            CoreMessage core = new CoreMessage();

            core.Id = Guid.NewGuid().ToString();
            core.Type = "https://example.org/vctp/1.0/push";

            var message = new BasicMessage();
            message.Text = String.Format("{{ vcaack : {0}, payload : {1} }}", vcaackJson, payloadJson);
            core.Body = message.ToByteString();

            core.Expires = expires;

            core.From = from;
            core.To.Add(to);

            return core;
        }
    }
}
