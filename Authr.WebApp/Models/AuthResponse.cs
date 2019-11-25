using System;
using IdentityModel.Client;

namespace Authr.WebApp.Models
{
    public class AuthResponse
    {
        public string Error { get; set; }
        public string ErrorDescription { get; set; }
        public string TokenType { get; set; }
        public int ExpiresIn { get; set; }
        public string IdToken { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string DeviceCode { get; set; }
        public string DeviceUserCode { get; set; }
        public string DeviceCodeVerificationUri { get; set; }
        public string Raw { get; set; }
        public bool HasError => !string.IsNullOrWhiteSpace(this.Error + this.ErrorDescription);
        public bool HasToken => !string.IsNullOrWhiteSpace(this.AccessToken + this.IdToken + this.RefreshToken);
        public bool HasDeviceCode => !string.IsNullOrWhiteSpace(this.DeviceCode + this.DeviceCodeVerificationUri);

        public static AuthResponse FromException(Exception exception)
        {
            return new AuthResponse
            {
                Error = exception.Message,
                ErrorDescription = exception.ToString(),
                Raw = exception.ToString()
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

        public static AuthResponse FromTokenResponse(TokenResponse response)
        {
            return new AuthResponse
            {
                AccessToken = response.AccessToken,
                IdToken = response.IdentityToken,
                TokenType = response.TokenType,
                RefreshToken = response.RefreshToken,
                ExpiresIn = response.ExpiresIn,
                Error = response.Error,
                ErrorDescription = response.ErrorDescription,
                Raw = response.Raw
            };
        }

        public static AuthResponse FromDeviceCodeResponse(DeviceAuthorizationResponse response)
        {
            return new AuthResponse
            {
                DeviceCode = response.DeviceCode,
                DeviceUserCode = response.UserCode,
                DeviceCodeVerificationUri = response.VerificationUri,
                Error = response.Error,
                ErrorDescription = response.ErrorDescription,
                Raw = response.Raw
            };
        }
    }
}