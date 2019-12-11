using System;

namespace Authr.WebApp.Models
{
    public class AuthRequest
    {
        public AuthRequestParameters Parameters { get; set; }
        public string Nonce { get; set; }
        public string State { get; set; }
        public string RequestedRedirectUrl { get; set; }
        public DateTimeOffset TimeCreated { get; set; } = DateTimeOffset.UtcNow;
        public bool IsInitiatedExternally { get; set; }
        public AuthResponse Response { get; set; }
    }
}