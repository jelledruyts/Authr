using System;
using System.Linq;
using Duende.IdentityModel.Client;
using Microsoft.AspNetCore.WebUtilities;

namespace Authr.WebApp.Models
{
    public class AuthRequestParameters
        : IdentityServiceImportRequestParameters // Allows requests to trigger an import of an Identity Service
    {
        public string RequestAction { get; set; }
        public string RequestType { get; set; }
        public string IdentityServiceId { get; set; }
        public string ClientApplicationId { get; set; }
        public string AuthorizationEndpoint { get; set; }
        public string TokenEndpoint { get; set; }
        public string DeviceCodeEndpoint { get; set; }
        public string SamlSignOnEndpoint { get; set; }
        public string SamlLogoutEndpoint { get; set; }
        public string WsFederationSignOnEndpoint { get; set; }
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
        public string Assertion { get; set; }
        public string SamlServiceProviderIdentifier { get; set; }
        public string WsFederationRealmIdentifier { get; set; }
        public bool SignRequest { get; set; }
        public string NameId { get; set; }
        public string SessionIndex { get; set; }
        public bool ForceAuthentication { get; set; }
        public bool SilentAuthentication { get; set; }
        public string RequestMethod { get; set; }
        public bool UsePkce { get; set; }
        public string GrantType { get; set; }
        public string AdditionalParameters { get; set; }

        public AuthRequestParameters()
        {
        }

        public AuthRequestParameters(AuthRequestParameters value)
            : base(value)
        {
            this.RequestAction = value.RequestAction;
            this.RequestType = value.RequestType;
            this.IdentityServiceId = value.IdentityServiceId;
            this.ClientApplicationId = value.ClientApplicationId;
            this.AuthorizationEndpoint = value.AuthorizationEndpoint;
            this.TokenEndpoint = value.TokenEndpoint;
            this.DeviceCodeEndpoint = value.DeviceCodeEndpoint;
            this.SamlSignOnEndpoint = value.SamlSignOnEndpoint;
            this.SamlLogoutEndpoint = value.SamlLogoutEndpoint;
            this.WsFederationSignOnEndpoint = value.WsFederationSignOnEndpoint;
            this.ClientId = value.ClientId;
            this.ClientSecret = value.ClientSecret;
            this.Scope = value.Scope;
            this.ResponseType = value.ResponseType;
            this.RedirectUri = value.RedirectUri;
            this.ResponseMode = value.ResponseMode;
            this.UserName = value.UserName;
            this.Password = value.Password;
            this.AuthorizationCode = value.AuthorizationCode;
            this.RefreshToken = value.RefreshToken;
            this.DeviceCode = value.DeviceCode;
            this.Assertion = value.Assertion;
            this.SamlServiceProviderIdentifier = value.SamlServiceProviderIdentifier;
            this.WsFederationRealmIdentifier = value.WsFederationRealmIdentifier;
            this.SignRequest = value.SignRequest;
            this.NameId = value.NameId;
            this.SessionIndex = value.SessionIndex;
            this.ForceAuthentication = value.ForceAuthentication;
            this.SilentAuthentication = value.SilentAuthentication;
            this.RequestMethod = value.RequestMethod;
            this.UsePkce = value.UsePkce;
            this.GrantType = value.GrantType;
            this.AdditionalParameters = value.AdditionalParameters;
        }

        public Parameters GetAdditionalParameters()
        {
            // The additional parameters string should be formed like a query string, i.e. "key1=value1&key2=value2...".
            var parameters = new Parameters();
            var additionalParameters = this.AdditionalParameters;
            if (!string.IsNullOrWhiteSpace(additionalParameters))
            {
                additionalParameters = additionalParameters.Replace(Environment.NewLine, "&").Replace('\n', '&'); // Replace newlines with '&' to form a single query string.
                var parsedParameters = QueryHelpers.ParseNullableQuery(additionalParameters);
                if (parsedParameters != null)
                {
                    foreach (var parameter in parsedParameters)
                    {
                        // If the same key has multiple values, only keep the first one, as multi-value
                        // keys cannot be represented in a dictionary, and they don't make sense here anyway.
                        parameters.Add(parameter.Key, parameter.Value.First());
                    }
                }
            }
            return parameters;
        }
    }
}