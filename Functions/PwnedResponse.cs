using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Net.Http.Headers;

namespace Functions
{
    /// <summary>
    /// Helper class which creates the response for a pwned passwords API request
    /// </summary>
    public static class PwnedResponse
    {
        /// <summary>
        /// Creates a response from the 
        /// </summary>
        /// <param name="req">Client HTTP request message</param>
        /// <param name="code">Status code to return to the client</param>
        /// <param name="content">The content to pass to the client. Either use this to return a status message or stream</param>
        /// <param name="stream">Stream from a file to pass as a response. This is primarily used for serving hash prefix files to clients.</param>
        /// <param name="lastModified">Last Modified date time to set for the response headers</param>
        /// <returns>Constructed HttpResponseData to serve to the client</returns>
        public static HttpResponseData CreateResponse(HttpRequestData req, HttpStatusCode code, string content = null, Stream stream = null, DateTimeOffset? lastModified = null)
        {
            var msg = req.CreateResponse(code);
            
            msg.Headers.Add(HeaderNames.ContentType, "text/plain");

            if (stream != null)
            {
                stream.CopyTo(msg.Body);
                
                if (lastModified != null)
                {
                    msg.Headers.Add(HeaderNames.LastModified, lastModified?.ToString("R"));
                }
            }
            else
            {
                msg.WriteString(content ?? string.Empty, new UTF8Encoding(false));
            }

            msg.Headers.Add(HeaderNames.CacheControl, new string[] {
                $"max-age={TimeSpan.FromDays(31).TotalSeconds}",
                "public"
            });

            msg.Headers.Add("Arr-Disable-Session-Affinity", "True");
            msg.Headers.Add(HeaderNames.AccessControlAllowOrigin, "*");

            return msg;
        }
    }
}
