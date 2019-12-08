using System;
using System.Collections.Generic;

namespace Authr.WebApp.Models
{
    public class ClientApplication
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public IList<string> Scopes { get; set; } = new List<string>();

        public static ClientApplication FromRequestParameters(string name, AuthRequestParameters requestParameters)
        {
            var clientApplication = new ClientApplication
            {
                Id = Guid.NewGuid().ToString(),
                Name = name,
            };
            clientApplication.Update(requestParameters);
            return clientApplication;
        }

        public void Update(AuthRequestParameters requestParameters)
        {
            this.ClientId = requestParameters.ClientId;
            this.ClientSecret = requestParameters.ClientSecret;
        }
    }
}