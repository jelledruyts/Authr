using System.Collections.Generic;

namespace Authr.WebApp.Models
{
    public class UserConfiguration
    {
        public string UserId { get; set; }
        public IList<IdentityService> IdentityServices { get; set; } = new List<IdentityService>();
        public IList<AuthRequestTemplate> RequestTemplates { get; set; } = new List<AuthRequestTemplate>();
    }
}