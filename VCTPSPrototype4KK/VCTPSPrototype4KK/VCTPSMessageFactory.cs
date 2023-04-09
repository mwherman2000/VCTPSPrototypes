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

namespace VCTPSPrototype4KK
{
    public static class MessageFactory
    {
        public const string ITSME = "https://example.org/knockknock/1.0/itsme";
        public const string INITIALIZE = "https://example.org/knockknock/1.0/initialize";
        public const string KNOCKKNOCK = "https://example.org/knockknock/1.0/knocknock";
        public const string WHOISTHERE = "https://example.org/knockknock/1.0/whoisthere";
        public static Dictionary<string, string> MessageTypes = new Dictionary<string, string>() {
            { ITSME, "poll" },
            { INITIALIZE, "notify" },
            { KNOCKKNOCK, "pull" },
            { WHOISTHERE, "push" }
        };

        // NewITSMEMsg: Do you have anything to send me? If you do, send me a 'notify' message with a VCA (which includes a payload identifier)
        public static CoreMessage NewITSMEMsg(string from, string[] to, long expires = 0)
        {
            CoreMessage core = new CoreMessage();

            core.Id = Guid.NewGuid().ToString();
            core.Type = ITSME;

            var message = new BasicMessage();
            message.Text = "{ }";
            core.Body = message.ToByteString();

            core.Expires = expires;

            core.From = from;
            core.To.Add(to);

            return core;
        }

        // NewINITIALIZEMsg: I have a payload for you. Here's a VCA (which includes a payload identifier) for you to acknowledge and agree to.
        //               Send me a 'pull' message containing a VCA Acknowledgement confirming your agreement with the VCA and I'll send you the payload
        public static CoreMessage NewINITIALIZEMsg(string from, string[] to, string vcaJson, long expires = 0)
        {
            CoreMessage core = new CoreMessage();

            core.Id = Guid.NewGuid().ToString();
            core.Type = INITIALIZE;

            var message = new BasicMessage();
            message.Text = String.Format("{{ vca : {0} }}", vcaJson);
            core.Body = message.ToByteString();

            core.Expires = expires;

            core.From = from;
            core.To.Add(to);

            return core;
        }

        // NewKNOCKKNOCKMsg: Here's a VCA Acknowledgement confirming that I agree to the VCA (which includes a payload identifier).
        //             Please send me a copy of the corresponding payload
        public static CoreMessage NewKNOCKKNOCKMsg(string from, string[] to, string vcaackJson, long expires = 0)
        {
            CoreMessage core = new CoreMessage();

            core.Id = Guid.NewGuid().ToString();
            core.Type = KNOCKKNOCK;

            var message = new BasicMessage();
            message.Text = String.Format("{{ vcaack : {0} }}", vcaackJson);
            core.Body = message.ToByteString();

            core.Expires = expires;

            core.From = from;
            core.To.Add(to);

            return core;
        }

        // NewWHOISTHEREMsg: Here's the payload you requested (and the corresponding VCA Acknowledgement you agreed to)
        public static CoreMessage NewWHOISTHEREMsg(string from, string[] to, string vcaackJson, string payloadJson, long expires = 0)
        {
            CoreMessage core = new CoreMessage();

            core.Id = Guid.NewGuid().ToString();
            core.Type = WHOISTHERE;

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
