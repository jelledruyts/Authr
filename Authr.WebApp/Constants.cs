namespace Authr.WebApp
{
    public static class Constants
    {
        public static class App
        {
            public const string Name = "Authr";
            public const string ProjectHomePage = "https://github.com/jelledruyts/Authr";
        }

        public static class ClaimTypes
        {
            public const string ObjectId = "oid";
        }

        public static class RequestTypes
        {
            public const string OpenIdConnect = nameof(OpenIdConnect);
            public const string Implicit = nameof(Implicit);
            public const string AuthorizationCode = nameof(AuthorizationCode);
            public const string ClientCredentials = nameof(ClientCredentials);
            public const string RefreshToken = nameof(RefreshToken);
            public const string ResourceOwnerPasswordCredentials = nameof(ResourceOwnerPasswordCredentials);
            public const string DeviceCode = nameof(DeviceCode);
            public const string DeviceToken = nameof(DeviceToken);
            public const string OnBehalfOf = nameof(OnBehalfOf);
            public const string Saml2AuthnRequest = nameof(Saml2AuthnRequest);
            public const string Saml2LogoutRequest = nameof(Saml2LogoutRequest);
            public const string WsFederationSignIn = nameof(WsFederationSignIn);
        }

        public static class CertificateNames
        {
            public const string SigningCertificate = nameof(SigningCertificate);
            public const string EncryptionCertificate = nameof(EncryptionCertificate);
        }

        public static class RequestMethods
        {
            public const string HttpRedirect = nameof(HttpRedirect);
            public const string HttpPost = nameof(HttpPost);
        }

        public static class IdentityServiceImportTypes
        {
            public const string Metadata = nameof(Metadata);
            public const string AzureAD = nameof(AzureAD);
            public const string AzureADB2C = nameof(AzureADB2C);
        }

        public static class RequestActions
        {
            public const string PerformRequest = nameof(PerformRequest);
        }
    }
}