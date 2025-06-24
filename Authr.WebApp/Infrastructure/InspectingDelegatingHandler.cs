using System;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Authr.WebApp.Infrastructure
{
    public class InspectingDelegatingHandler : DelegatingHandler
    {
        public const string RequestLogHeader = "X-Request-Log";
        public const string ResponseLogHeader = "X-Response-Log";

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Get request information.
            var requestLog = new StringBuilder();
            requestLog.AppendLine($"{request.Method} {request.RequestUri}");
            requestLog.AppendLine(request.Headers.ToString());
            if (request.Content != null)
            {
                requestLog.AppendLine(await request.Content.ReadAsStringAsync());
            }

            // Call the inner handler.
            var response = await base.SendAsync(request, cancellationToken);

            // Get response information.
            var responseLog = new StringBuilder();
            responseLog.AppendLine($"HTTP/{response.Version} {(int)response.StatusCode} {response.ReasonPhrase}");
            responseLog.AppendLine(response.Headers.ToString());
            if (response.Content != null)
            {
                responseLog.AppendLine(await response.Content.ReadAsStringAsync());
            }

            // Add request and response information to the headers so they can be retrieved
            // directly from the response.
            SetLogHeaderValue(response, RequestLogHeader, requestLog.ToString());
            SetLogHeaderValue(response, ResponseLogHeader, responseLog.ToString());

            return response;
        }

        public static void SetLogHeaderValue(HttpResponseMessage request, string logHeaderName, string rawValue)
        {
            if (rawValue != null)
            {
                request.Headers.Add(logHeaderName, Convert.ToBase64String(Encoding.UTF8.GetBytes(rawValue)));
            }
        }

        public static string GetRequestLog(HttpResponseMessage response)
        {
            return GetLogHeaderValue(response, RequestLogHeader);
        }

        public static string GetResponseLog(HttpResponseMessage response)
        {
            return GetLogHeaderValue(response, ResponseLogHeader);
        }

        public static string GetLogHeaderValue(HttpResponseMessage response, string logHeaderName)
        {
            if (response.Headers.TryGetValues(logHeaderName, out var values))
            {
                var log = values.FirstOrDefault();
                return log != null ? Encoding.UTF8.GetString(Convert.FromBase64String(log)) : null;
            }
            return null;
        }
    }
}