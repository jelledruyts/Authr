using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.WebUtilities;

namespace Authr.WebApp.Models
{
    public class AuthRequestParameters
    {
        public string RequestType { get; set; }
        public string RequestTemplateId { get; set; }
        public string IdentityServiceId { get; set; }
        public string ClientApplicationId { get; set; }
        public string MetadataEndpoint { get; set; }
        public string AuthorizationEndpoint { get; set; }
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
        public string AdditionalParameters { get; set; }

        public AuthRequestParameters Clone()
        {
            return new AuthRequestParameters
            {
                RequestType = this.RequestType,
                AuthorizationEndpoint = this.AuthorizationEndpoint,
                TokenEndpoint = this.TokenEndpoint,
                DeviceCodeEndpoint = this.DeviceCodeEndpoint,
                ClientId = this.ClientId,
                ClientSecret = this.ClientSecret,
                Scope = this.Scope,
                ResponseType = this.ResponseType,
                RedirectUri = this.RedirectUri,
                ResponseMode = this.ResponseMode,
                UserName = this.UserName,
                Password = this.Password,
                AuthorizationCode = this.AuthorizationCode,
                RefreshToken = this.RefreshToken,
                DeviceCode = this.DeviceCode,
                AdditionalParameters = this.AdditionalParameters
            };
        }

        public IDictionary<string, string> GetAdditionalParameters()
        {
            // The additional parameters string should be formed like a query string, i.e. "key1=value1&key2=value2...".
            var parameters = new Dictionary<string, string>();
            var parsedParameters = QueryHelpers.ParseNullableQuery(this.AdditionalParameters);
            if (parsedParameters != null)
            {
                foreach (var parameter in parsedParameters)
                {
                    // If the same key has multiple values, only keep the first one, as multi-value
                    // keys cannot be represented in a dictionary, and they don't make sense here anyway.
                    parameters.Add(parameter.Key, parameter.Value.First());
                }
            }
            return parameters;
        }
    }
}