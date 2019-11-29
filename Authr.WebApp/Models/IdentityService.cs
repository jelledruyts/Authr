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
    }
}