using System;
using System.Collections.Generic;

namespace Authr.WebApp.Models
{
    public class IdentityService
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string MetadataEndpoint { get; set; }
        public string AuthorizationEndpoint { get; set; }
        public string TokenEndpoint { get; set; }
        public string DeviceCodeEndpoint { get; set; }
        public IList<ClientApplication> ClientApplications { get; set; } = new List<ClientApplication>();

        public static IdentityService FromRequestParameters(string name, AuthRequestParameters requestParameters)
        {
            var identityService = new IdentityService
            {
                Id = Guid.NewGuid().ToString(),
                Name = name,
            };
            identityService.Update(requestParameters);
            return identityService;
        }

        public void Update(AuthRequestParameters requestParameters)
        {
            this.MetadataEndpoint = requestParameters.MetadataEndpoint;
            this.AuthorizationEndpoint = requestParameters.AuthorizationEndpoint;
            this.TokenEndpoint = requestParameters.TokenEndpoint;
            this.DeviceCodeEndpoint = requestParameters.DeviceCodeEndpoint;
        }
    }
}