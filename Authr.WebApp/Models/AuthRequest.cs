using System;

namespace Authr.WebApp.Models
{
    public class AuthRequest
    {
        public AuthRequestParameters Parameters { get; set; }
        public string Nonce { get; set; }
        public string State { get; set; }
        public DateTimeOffset? TimeCreated { get; set; }

        public AuthRequest(AuthRequestParameters parameters)
        {
            this.Parameters = parameters;
            this.Nonce = Guid.NewGuid().ToString();
            this.State = Guid.NewGuid().ToString();
            this.TimeCreated = DateTimeOffset.UtcNow;
        }
    }
}