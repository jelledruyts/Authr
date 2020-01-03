namespace Authr.WebApp.Models
{
    public class IdentityServiceImportRequestParameters
    {
        public string ImportType { get; set; }
        public string FederationMetadataUrl { get; set; }
        public string OpenIdConnectMetadataUrl { get; set; }
        public string Tenant { get; set; }
        public string PolicyId { get; set; }
    }
}