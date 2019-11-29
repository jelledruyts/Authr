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
    }
}