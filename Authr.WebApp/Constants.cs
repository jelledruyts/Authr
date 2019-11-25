namespace Authr.WebApp
{
    public static class Constants
    {
        public static class RequestTypes
        {
            public const string AuthorizationCode = nameof(AuthorizationCode);
            public const string ClientCredentials = nameof(ClientCredentials);
            public const string RefreshToken = nameof(RefreshToken);
            public const string ResourceOwnerPasswordCredentials = nameof(ResourceOwnerPasswordCredentials);
            public const string DeviceCode = nameof(DeviceCode);
            public const string DeviceToken = nameof(DeviceToken);
        }
    }
}