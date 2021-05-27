using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

namespace Functions
{
    public static class PwnedResponse
    {
        public static HttpResponseMessage CreateResponse(HttpRequestMessage req, HttpStatusCode code, string content = null, Stream stream = null, DateTimeOffset? lastModified = null)
        {
            var msg = new HttpResponseMessage(code);

            if (stream != null)
            {
                msg.Content = new StreamContent(stream);
                msg.Content.Headers.ContentType = new MediaTypeHeaderValue("text/plain");

                if (lastModified != null)
                {
                    msg.Content.Headers.LastModified = lastModified;
                }
            }
            else
            {
                msg.Content = content == null ? null : new StringContent(content, new UTF8Encoding(false), "text/plain");
            }

            msg.Headers.CacheControl = new CacheControlHeaderValue
            {
                MaxAge = TimeSpan.FromDays(31),
                Public = true
            };

            msg.Headers.Add("Arr-Disable-Session-Affinity", "True");
            msg.Headers.Add("Access-Control-Allow-Origin", "*");

            return msg;
        }
    }
}
