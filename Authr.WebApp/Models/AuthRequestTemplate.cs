using System;

namespace Authr.WebApp.Models
{
    public class AuthRequestTemplate
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public AuthRequestParameters RequestParameters { get; set; }

        public static AuthRequestTemplate FromRequestParameters(string name, AuthRequestParameters requestParameters)
        {
            var requestTemplate = new AuthRequestTemplate
            {
                Id = Guid.NewGuid().ToString(),
                Name = name,
            };
            requestTemplate.Update(requestParameters);
            return requestTemplate;
        }

        public void Update(AuthRequestParameters requestParameters)
        {
            this.RequestParameters = requestParameters;
        }
    }
}