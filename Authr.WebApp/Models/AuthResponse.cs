using System;
using System.Net.Http;
using Authr.WebApp.Infrastructure;
using Duende.IdentityModel.Client;

namespace Authr.WebApp.Models
{
    public class AuthResponse
    {
        public string Error { get; set; }
        public string ErrorDescription { get; set; }
        public string TokenType { get; set; }
        public int? ExpiresIn { get; set; }
        public string IdToken { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string AuthorizationCode { get; set; }
        public string DeviceCode { get; set; }
        public string DeviceUserCode { get; set; }
        public string DeviceCodeVerificationUri { get; set; }
        public string SamlRequest { get; set; }
        public string SamlResponse { get; set; }
        public string WsFederationResponse { get; set; }
        public string Raw { get; set; }
        public string HttpRequestLog { get; set; }
        public string HttpResponseLog { get; set; }
        public DateTimeOffset TimeCreated { get; set; } = DateTimeOffset.UtcNow;

        public AuthResponse()
        {
        }

        public AuthResponse(HttpResponseMessage httpResponseMessage)
        {
            this.HttpRequestLog = InspectingDelegatingHandler.GetRequestLog(httpResponseMessage);
            this.HttpResponseLog = InspectingDelegatingHandler.GetResponseLog(httpResponseMessage);
        }

        public static AuthResponse FromException(Exception value)
        {
            return new AuthResponse
            {
                Error = value.Message
            };
        }

        public static AuthResponse FromError(string error, string errorDescription)
        {
            return new AuthResponse
            {
                Error = error,
                ErrorDescription = errorDescription
            };
        }

        public static AuthResponse FromAuthResponseParameters(AuthResponseParameters value)
        {
            return new AuthResponse
            {
                Error = value.Error,
                ErrorDescription = value.ErrorDescription,
                TokenType = value.TokenType,
                IdToken = value.IdToken,
                AccessToken = value.AccessToken,
                RefreshToken = value.RefreshToken,
                AuthorizationCode = value.AuthorizationCode,
                SamlRequest = value.SamlRequest,
                SamlResponse = value.SamlResponse,
                WsFederationResponse = value.Wresult
            };
        }

        public static AuthResponse FromTokenResponse(TokenResponse value)
        {
            return new AuthResponse(value.HttpResponse)
            {
                Error = value.Error,
                ErrorDescription = value.ErrorDescription,
                AccessToken = value.AccessToken,
                IdToken = value.IdentityToken,
                TokenType = value.TokenType,
                RefreshToken = value.RefreshToken,
                ExpiresIn = value.ExpiresIn,
                Raw = value.Raw
            };
        }

        public static AuthResponse FromDeviceCodeResponse(DeviceAuthorizationResponse value)
        {
            return new AuthResponse(value.HttpResponse)
            {
                DeviceCode = value.DeviceCode,
                DeviceUserCode = value.UserCode,
                DeviceCodeVerificationUri = value.VerificationUri,
                Error = value.Error,
                ErrorDescription = value.ErrorDescription,
                Raw = value.Raw
            };
        }
    }
}