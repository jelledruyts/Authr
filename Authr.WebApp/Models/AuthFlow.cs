using System;
using System.Collections.Generic;
using Duende.IdentityModel;

namespace Authr.WebApp.Models
{
    public class AuthFlow
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string UserId { get; set; }
        public string RequestType { get; set; }
        public DateTimeOffset TimeCreated { get; set; } = DateTimeOffset.UtcNow;
        public DateTimeOffset? TimeCompleted { get; set; }
        public bool IsComplete { get; set; }
        public IList<AuthRequest> Requests { get; set; } = new List<AuthRequest>();

        public AuthRequest AddRequest(AuthRequestParameters parameters)
        {
            var request = new AuthRequest()
            {
                Parameters = parameters,
                Nonce = CryptoRandom.CreateUniqueId(32),
                FlowId = this.Id,
                IsInitiatedExternally = false
            };
            this.Requests.Add(request);
            return request;
        }

        public AuthRequest AddExternallyInitiatedRequest()
        {
            var request = new AuthRequest()
            {
                IsInitiatedExternally = true
            };
            this.Requests.Add(request);
            return request;
        }
    }
}