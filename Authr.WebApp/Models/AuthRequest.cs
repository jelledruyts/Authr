using System;

namespace Authr.WebApp.Models
{
    // TODO: Put actual user input in AuthRequestParameters class, and external response in AuthResponseParameters.
    public class AuthRequest
    {
        public string RequestType { get; set; }
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
        public string Nonce { get; set; }
        public string State { get; set; }
        public DateTimeOffset? TimeCreated { get; set; }

        public AuthRequest Clone()
        {
            return new AuthRequest
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
                DeviceCode = this.DeviceCode
            };
        }
    }
}