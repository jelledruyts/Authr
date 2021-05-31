namespace Authr.WebApp.Models
{
    public class IdentityServiceImportRequestParameters
    {
        public string ImportType { get; set; }
        public string FederationMetadataUrl { get; set; }
        public string OpenIdConnectMetadataUrl { get; set; }
        public string Tenant { get; set; }
        public string PolicyId { get; set; }

        public IdentityServiceImportRequestParameters()
        {
        }

        public IdentityServiceImportRequestParameters(IdentityServiceImportRequestParameters value)
        {
            this.ImportType = value.ImportType;
            this.FederationMetadataUrl = value.FederationMetadataUrl;
            this.OpenIdConnectMetadataUrl = value.OpenIdConnectMetadataUrl;
            this.Tenant = value.Tenant;
            this.PolicyId = value.PolicyId;
        }
    }
}