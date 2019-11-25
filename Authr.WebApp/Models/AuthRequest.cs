using System;

namespace Authr.WebApp.Models
{
    public class AuthRequest
    {
        public string RequestType { get; set; }
        public string AuthorizeEndpoint { get; set; }
        public string TokenEndpoint { get; set; }
        public string DeviceCodeEndpoint { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Scope { get; set; }
        public string ResponseType { get; set; }
        public string RedirectUri { get; set; }
        public string ResponseMode { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string AuthorizationCode { get; set; }
        public string RefreshToken { get; set; }
        public string DeviceCode { get; set; }
        public string Nonce { get; set; }
        public string State { get; set; }
        public string RequestUrl { get; set; }
        public DateTimeOffset TimeCreated { get; set; } = DateTimeOffset.UtcNow;
    }
}